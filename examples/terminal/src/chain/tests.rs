use super::{
    app::{App, Finalized, MAX_TIMESTAMP_DRIFT, initial_sync_target},
    client::{Chain as _, Client, EFFECT_ATTEMPTS, POLL, RECENCY_THRESHOLD},
    da, harness, ingress, light,
    node::{self, Node},
    query::{
        self, CertifiedRead, Evidence, EvidenceBody, EvidenceLookup, EvidenceRequest,
        EvidenceResponse, Lookup, ReadRequest, ReadResponse,
    },
    setup::{Genesis, ValidatorEntry},
    state::{
        Advice, FaultRecord, HardFaultReasonResponse, Record, Reject, admitted_key, advise,
        anchor_key, claim_roots_key, deposit_key, execute, fault_key, hard_fault_key, refund_key,
        registration_key, status_key, withdrawal_key,
    },
    tx::{
        AdmitRequest, BeginHardFaultSettlementRequest, ChallengeRequest, ClaimHardFaultRequest,
        ClaimPendingDepositRequest, DepositRequest, MAX_CHALLENGE_BYTES, QueueWithdrawalRequest,
        RegisterEpochRequest, SettlementTx, WithdrawalClaimRequest,
    },
    types::{Block, Database, MAX_BLOCK_BYTES, MAX_BLOCK_TXS, MAX_TX_BYTES, Qmdb, StateKey, now},
    validator::{
        MAX_MESSAGE_SIZE, NAMESPACE as CHAIN_NAMESPACE, SHARING_MODE, Scheme as Threshold,
    },
};
use crate::{
    agent::{Agent, PaymentOutcome, WithdrawalOutcome},
    operator::{Operator, rpc as operator_rpc},
    protocol::{
        AccountCache, Deployment, DepositEvent, INITIAL_BALANCE, Key, MAX_SLICES, PreparedEpoch,
        Protocol, SLICE_BITS, SettlementResult, Timing, accounts, chain_id, clearing_private,
        committee, dealt_participant, deployment, deployments, identities, operator_ack_key,
        operator_ack_signer, operator_key, operator_signer, wallets,
    },
    rpc,
    service::{observe, prepare_request},
};
use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use commonware_broadcast::buffered;
use commonware_clearing::bajillion::{
    admission::{assigned_slice_spans, slice_holders},
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{AckWitness, Challenge, ChallengeKind},
    commitment::{VectorKind, VectorRoot},
    payment::{VectorAck, VectorSendBody},
    state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    transition::{Assignment, BatchId, StateCache, WithdrawalClaim, account_slice},
    vector::OutVector,
};
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode as _, EncodeSize as _, Error as CodecError, RangeCfg,
    Write as _,
};
use commonware_consensus::{
    Reporters,
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{
        self,
        config::{ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
        mocks::scheme::{self as scheme_mocks, Scheme as MockScheme},
        scheme::Scheme as CertScheme,
        types::{Context, Finalization, Finalize, Proposal},
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digest as _, Digestible as _, Hasher as _, Sha256, Signer as _,
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{group::Share, ops::compute_public, variant::MinSig},
    },
    certificate::{ConstantProvider, Signers, mocks::Fixture as SchemeFixture},
    ed25519,
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::Signature;
use commonware_glue::{
    simulate::{
        engine::{EngineDefinition, InitContext},
        exit::ExitCondition,
        plan::PlanBuilder,
        processed::ProcessedHeight,
        property::Property,
        reporter::MonitorReporter,
        tracker::ProgressTracker,
    },
    stateful::{
        Application as _, Config as StatefulConfig, Input, Stateful as StatefulActor, SyncPlan,
        db::{AttachableResolver, DatabaseSet, Merkleized as _, Shared, SyncEngineConfig},
    },
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock as _, Handle, Listener, Network as _, Quota, Runner as _, Spawner as _,
    Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    archive::prunable,
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::full::Config as MerkleConfig,
    mmr,
    qmdb::{
        any::ordered::variable::Operation,
        current::VariableConfig,
        sync::{FeedbackTx, Request, Response, Source as QmdbSource},
    },
    translator::TwoCap,
};
use commonware_utils::{
    N3f1, NZU16, NZU32, NZU64, NZUsize, Participant, TestRng, iter::NonEmpty, non_empty_range,
    ordered::Set, sync::Mutex, test_rng,
};
use std::{
    convert::Infallible,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const PAGE_SIZE: std::num::NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);

/// Settlement QMDB config with partitions derived from `prefix`.
fn config(
    prefix: &str,
    pooler: &impl BufferPooler,
) -> VariableConfig<TwoCap, ((), ()), Sequential> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-chain-mmr-journal"),
            metadata_partition: format!("{prefix}-chain-mmr-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: IO_BUFFER_SIZE,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VariableJournalConfig {
            partition: format!("{prefix}-chain-log-journal"),
            items_per_section: NZU64!(7),
            compression: None,
            codec_config: ((), ()),
            page_cache,
            write_buffer: IO_BUFFER_SIZE,
        },
        grafted_metadata_partition: format!("{prefix}-chain-grafted-metadata"),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// Opens a fresh settlement database with partitions under `prefix`.
async fn open(context: deterministic::Context, prefix: &str) -> Database<deterministic::Context> {
    let config = config(prefix, &context);
    <Database<deterministic::Context> as DatabaseSet<_>>::init(context, config).await
}

/// Executes one block against `db` under `timing` and applies it, returning
/// the block's (canonical root, ops root). The height doubles as the
/// timestamp, which keeps timestamps strictly monotonic.
async fn seal_at(
    db: &Database<deterministic::Context>,
    height: u64,
    timing: &Timing,
    txs: &[SettlementTx],
) -> (Digest, Digest) {
    let batch = db.new_batches().await;
    let sealed = execute(
        batch,
        Height::new(height),
        height,
        timing,
        &deployments(),
        txs,
    )
    .await
    .expect("block execution succeeds");
    let roots = (sealed.root(), sealed.ops_root());
    db.apply(sealed).await;
    roots
}

/// Executes one block against `db` under the default timing and applies it.
async fn seal(
    db: &Database<deterministic::Context>,
    height: u64,
    txs: &[SettlementTx],
) -> (Digest, Digest) {
    seal_at(db, height, &Timing::DEFAULT, txs).await
}

/// Executes one block against `db` under an explicit deployment set with the
/// default timing and applies it.
async fn seal_with(
    db: &Database<deterministic::Context>,
    height: u64,
    configured: &[Deployment],
    txs: &[SettlementTx],
) -> (Digest, Digest) {
    let batch = db.new_batches().await;
    let sealed = execute(
        batch,
        Height::new(height),
        height,
        &Timing::DEFAULT,
        configured,
        txs,
    )
    .await
    .expect("block execution succeeds");
    let roots = (sealed.root(), sealed.ops_root());
    db.apply(sealed).await;
    roots
}

/// The two-deployment configuration the tenancy tests run: the compiled
/// default deployment plus a second operator's deployment over the same
/// account set.
fn two_deployments() -> Vec<Deployment> {
    vec![
        Deployment::new(operator_key(), operator_ack_key(0), accounts()),
        Deployment::new(
            operator_signer(1).public_key(),
            operator_ack_key(1),
            accounts(),
        ),
    ]
}

/// Reads one record from applied state.
async fn read(db: &Database<deterministic::Context>, key: &StateKey) -> Option<Record> {
    db.read().await.get(key).await.expect("state read succeeds")
}

/// One certified-read request against the compiled default deployment.
fn req(lookup: Lookup) -> ReadRequest {
    ReadRequest::new(deployment(), lookup)
}

/// One deposit transaction naming the compiled default deployment.
fn deposit_tx(event: DepositEvent) -> SettlementTx {
    SettlementTx::Deposit(DepositRequest {
        deployment: deployment(),
        event,
    })
}

/// Reads the live registration record, panicking on a proven absence.
async fn registration(db: &Database<deterministic::Context>) -> super::state::RegistrationRecord {
    match read(db, &registration_key(&deployment())).await {
        Some(Record::Registration(record)) => record,
        record => panic!("expected the registration record, found {record:?}"),
    }
}

/// Reads the status singleton.
async fn status(db: &Database<deterministic::Context>) -> super::state::StatusRecord {
    match read(db, &status_key(&deployment())).await {
        Some(Record::Status(status)) => status,
        record => panic!("expected the status record, found {record:?}"),
    }
}

/// The genesis account cache backing every deployment in these tests.
fn genesis_cache() -> AccountCache {
    let mut leaves = identities()
        .into_iter()
        .map(|identity| StateLeaf {
            account: identity.key,
            state: AccountState {
                balance: INITIAL_BALANCE,
                active: true,
                ..AccountState::default()
            },
        })
        .collect::<Vec<_>>();
    leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
    StateCache::new::<Sha256>(leaves).expect("genesis accounts are well formed")
}

/// One epoch's chain transactions: a unit deposit to the first predecessor
/// account, the boundary-only signed registration, and the certified close
/// admitting it.
struct EpochTxs {
    deposit: DepositEvent,
    deposit_tx: SettlementTx,
    register_tx: SettlementTx,
    admit_tx: SettlementTx,
    result: SettlementResult,
    /// Account leaves after the close settles.
    successor: Vec<StateLeaf<Key>>,
}

/// One epoch's fixture before certification: the chain transactions up to
/// admission and the prepared close awaiting a certificate.
struct EpochBuild {
    deposit: DepositEvent,
    deposit_tx: SettlementTx,
    register_tx: SettlementTx,
    prepared: PreparedEpoch,
    /// Account leaves after the close settles.
    successor: Vec<StateLeaf<Key>>,
}

/// The unit-deposit boundary every fixture registers over `predecessor`
/// leaves: the deposit event, its transaction, and the boundary-only signed
/// registration transaction (byte-identical regardless of the deadlines the
/// chain later assigns at inclusion).
fn fixture_boundary(
    protocol: &Protocol,
    epoch: u64,
    predecessor: &[StateLeaf<Key>],
    deposit_label: &'static [u8],
) -> (DepositEvent, SettlementTx, SettlementTx) {
    let account = predecessor[0].account.clone();
    let liability = predecessor
        .iter()
        .map(|leaf| leaf.state.balance)
        .sum::<u64>();
    let deposit = DepositEvent {
        id: Sha256::hash(&[deposit_label]),
        account: account.clone(),
        amount: 1,
    };
    let deposits = DepositBatch::new(vec![DepositRecord::new(account, 1).unwrap()]).unwrap();
    let deposits_root = deposits.root::<Sha256>().unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let signature = protocol.sign_chain_registration(
        epoch,
        liability,
        &deposits_root,
        &deposits_root,
        &withdrawals,
    );
    let register = RegisterEpochRequest {
        deployment: protocol.deployment(),
        epoch,
        predecessor_liability: liability,
        deposits_root,
        staged_root: deposits_root,
        withdrawals,
        openings: Vec::new(),
        signature,
    };
    (
        deposit.clone(),
        SettlementTx::Deposit(DepositRequest {
            deployment: protocol.deployment(),
            event: deposit,
        }),
        SettlementTx::RegisterEpoch(register),
    )
}

/// Builds one epoch's prepared fixture over `predecessor` leaves with
/// explicit block-height deadlines (the pair the chain assigns at the
/// registration's inclusion height), stopping before certification.
fn build_fixture(
    protocol: &Protocol,
    epoch: u64,
    predecessor: Vec<StateLeaf<Key>>,
    deposit_label: &'static [u8],
    admission_deadline: u64,
    challenge_deadline: u64,
) -> EpochBuild {
    let account = predecessor[0].account.clone();
    let liability = predecessor
        .iter()
        .map(|leaf| leaf.state.balance)
        .sum::<u64>();
    let (deposit, deposit_tx, register_tx) =
        fixture_boundary(protocol, epoch, &predecessor, deposit_label);
    let deposits =
        DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
    let withdrawals = WithdrawalBatch::empty();

    let predecessor_state = predecessor[0].state;
    let successor_state = AccountState {
        balance: predecessor_state.balance + 1,
        ..predecessor_state
    };
    let row = AccountRow {
        account: account.clone(),
        predecessor: predecessor_state,
        successor: successor_state,
        outgoing: None,
        output: SettlementOutput::None,
        prefix: Prefix {
            deposit: 1,
            ..Prefix::default()
        },
    };
    let mut successor = predecessor.clone();
    successor[0].state = successor_state;
    let registration = protocol
        .registration_at(
            epoch,
            deposits,
            withdrawals,
            liability,
            admission_deadline,
            challenge_deadline,
        )
        .unwrap();
    let prepared = protocol
        .prepare(
            registration,
            vec![deposit.clone()],
            predecessor,
            vec![row],
            vec![OutVector::empty(epoch, account)],
            vec![None],
            Vec::new(),
            successor.clone(),
        )
        .unwrap();
    EpochBuild {
        deposit_tx,
        register_tx,
        deposit,
        prepared,
        successor,
    }
}

/// Builds one epoch's fixture over `predecessor` leaves with explicit
/// block-height deadlines, certified through the in-process harness
/// simulation, as the deposit, registration, and admission transactions.
fn close_fixture(
    protocol: &Protocol,
    epoch: u64,
    predecessor: Vec<StateLeaf<Key>>,
    deposit_label: &'static [u8],
    admission_deadline: u64,
    challenge_deadline: u64,
) -> EpochTxs {
    let build = build_fixture(
        protocol,
        epoch,
        predecessor,
        deposit_label,
        admission_deadline,
        challenge_deadline,
    );
    let result = protocol
        .complete(build.prepared, &mut TestRng::new(91))
        .unwrap();
    EpochTxs {
        deposit_tx: build.deposit_tx,
        register_tx: build.register_tx,
        admit_tx: SettlementTx::Admit(AdmitRequest::from(&result)),
        deposit: build.deposit,
        result,
        successor: build.successor,
    }
}

/// The epoch-0 fixture: a registration included at height 1, whose assigned
/// deadlines under the default policy are the admission deadline at height
/// 11 and the challenge deadline at height 12.
struct EpochFixture {
    deposit: DepositEvent,
    deposit_tx: SettlementTx,
    register_tx: SettlementTx,
    admit_tx: SettlementTx,
    result: SettlementResult,
    state: AccountCache,
    protocol: Protocol,
}

fn epoch_fixture() -> EpochFixture {
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let state = genesis_cache();
    let txs = close_fixture(
        &protocol,
        0,
        state.leaves().to_vec(),
        b"chain-fixture-deposit",
        11,
        12,
    );
    EpochFixture {
        deposit: txs.deposit,
        deposit_tx: txs.deposit_tx,
        register_tx: txs.register_tx,
        admit_tx: txs.admit_tx,
        result: txs.result,
        state,
        protocol,
    }
}

/// An operator acknowledgment fork over the fixture's payment context,
/// parameterized by the forked cumulative debits so distinct valid fraud
/// evidence can be built against one close: two countersigned endpoints at
/// one payer sequence number with different bodies.
fn ack_fork(
    result: &SettlementResult,
    protocol: &Protocol,
    amounts: (u64, u64),
) -> Challenge<Key, Digest> {
    let wallets = wallets();
    let payer = &wallets[0];
    let send_root = VectorRoot {
        digest: Sha256::hash(&[b"chain-ack-fork-send-root"]),
    };
    let ack = |cumulative_debit: u64| {
        let body = VectorSendBody::new(
            &result.payment_context,
            payer.public_key(),
            0,
            cumulative_debit,
            send_root,
        );
        VectorAck::sign_by_authorities(body, payer.signer(), protocol.operator())
    };
    Challenge::AckFork {
        left: Box::new(AckWitness::from_ack(&ack(amounts.0))),
        right: Box::new(AckWitness::from_ack(&ack(amounts.1))),
    }
}

/// A signed empty epoch-0 registration: the boundary alone, with the
/// deadlines left to execution at the inclusion height.
fn empty_register_tx() -> SettlementTx {
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let signature = protocol.sign_chain_registration(0, 400, &root, &root, &withdrawals);
    SettlementTx::RegisterEpoch(RegisterEpochRequest {
        deployment: protocol.deployment(),
        epoch: 0,
        predecessor_liability: 400,
        deposits_root: root,
        staged_root: root,
        withdrawals,
        openings: Vec::new(),
        signature,
    })
}

/// The harness serves validator evidence over the real wire from the closes
/// the in-process simulation sealed: every account's state openings and the
/// slice intervals verify against the certified roots, routing advice
/// matches the validators', and a close is pruned once the chain passes its
/// challenge deadline.
#[test]
fn harness_serves_validator_evidence() {
    deterministic::Runner::default().start(|context| async move {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], 6_500));
        let control = harness::start(&context, address, "harness-evidence").await;
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();

        // The boundary transactions are deadline-independent, so the close is
        // built once the chain has assigned the registration's deadlines.
        let (_, deposit_tx, register_tx) =
            fixture_boundary(&protocol, 0, state.leaves(), b"harness-evidence-deposit");
        control.submit(deposit_tx).await;
        let (registered_at, _) = control.submit(register_tx).await;
        let admission_deadline = registered_at + Timing::DEFAULT.admission_offset;
        let challenge_deadline = admission_deadline + Timing::DEFAULT.challenge_duration;
        let txs = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"harness-evidence-deposit",
            admission_deadline,
            challenge_deadline,
        );
        control.submit(txs.admit_tx.clone()).await;
        assert!(matches!(
            control
                .record(admitted_key(&deployment(), 0))
                .await,
            Some(Record::Admitted(admitted)) if admitted.roots == txs.result.roots
        ));
        let batch = txs.result.finalized.batch_id.into_digest();
        let successor = StateCache::new::<Sha256>(txs.successor.clone()).unwrap();
        assert_eq!(successor.root(), txs.result.roots.successor);

        // Every account's state openings arrive through the wire, from the
        // holders genesis routes to, and match the whole-tree openings.
        let client = Client::new(
            control.identity(),
            deployment(),
            vec![address],
            context.child("client_rng"),
        )
        .unwrap();
        for leaf in state.leaves() {
            let account = leaf.account.clone();
            for (lookup, cache, root) in [
                (
                    EvidenceLookup::PredecessorState {
                        batch,
                        account: account.clone(),
                    },
                    &state,
                    txs.result.predecessor_root,
                ),
                (
                    EvidenceLookup::SuccessorState {
                        batch,
                        account: account.clone(),
                    },
                    &successor,
                    txs.result.roots.successor,
                ),
            ] {
                let EvidenceResponse::Served(Evidence::Close {
                    header,
                    roots,
                    body: EvidenceBody::State(opening),
                }) = client.evidence(&context, lookup).await.unwrap()
                else {
                    panic!("the harness did not serve the state opening");
                };
                assert_eq!(header, txs.result.header);
                assert_eq!(roots, txs.result.roots);
                assert_eq!(opening, cache.opening(&account).unwrap());
                opening
                    .proof
                    .verify::<Sha256>(VectorKind::State, &root, opening.leaf.encode().as_ref())
                    .unwrap();
            }
            let EvidenceResponse::Served(Evidence::Genesis(opening)) = client
                .evidence(&context, EvidenceLookup::GenesisState { account })
                .await
                .unwrap()
            else {
                panic!("the harness did not serve the genesis opening");
            };
            assert_eq!(opening, state.opening(&leaf.account).unwrap());
        }

        // Every slice's interval verifies at the successor root and at the
        // genesis root, and the harness classifies unknown work like a
        // validator does.
        for slice in 0..MAX_SLICES as u16 {
            for (root, leaves) in [
                (txs.result.roots.successor, successor.leaves()),
                (state.root(), state.leaves()),
            ] {
                let EvidenceResponse::Served(Evidence::Interval(range)) = client
                    .evidence(&context, EvidenceLookup::Interval { root, slice })
                    .await
                    .unwrap()
                else {
                    panic!("the harness did not serve the interval");
                };
                range.verify(&root, slice, SLICE_BITS).unwrap();
                let expected = leaves
                    .iter()
                    .filter(|leaf| account_slice(&leaf.account, SLICE_BITS).unwrap() == slice)
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(range.members, expected);
            }
        }
        let account = state.leaves()[0].account.clone();
        assert_eq!(
            client
                .evidence(
                    &context,
                    EvidenceLookup::PredecessorState {
                        batch: Sha256::hash(&[b"unknown-batch"]),
                        account: account.clone(),
                    },
                )
                .await
                .unwrap(),
            EvidenceResponse::Unsealed
        );
        assert_eq!(
            control
                .evidence(EvidenceRequest::new(
                    Sha256::hash(&[b"foreign-deployment"]),
                    EvidenceLookup::PredecessorState {
                        batch,
                        account: account.clone(),
                    },
                ))
                .await,
            EvidenceResponse::Unknown
        );

        // Past the challenge deadline the close finalizes and its dealing is
        // released, exactly as a validator prunes it.
        let height = control.advance(0).await;
        control.advance(challenge_deadline + 1 - height).await;
        assert_eq!(
            client
                .evidence(
                    &context,
                    EvidenceLookup::PredecessorState { batch, account },
                )
                .await
                .unwrap(),
            EvidenceResponse::Pruned
        );
    });
}

#[test]
fn deposits_dedupe_by_id_and_conflicts_are_provable() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("deposit_dedupe"), "deposit-dedupe").await;
        let account = identities()[0].key.clone();
        let deposit = DepositEvent {
            id: Sha256::hash(&[b"chain-deposit-id"]),
            account,
            amount: 7,
        };
        let tx = deposit_tx(deposit.clone());
        seal(&db, 1, std::slice::from_ref(&tx)).await;
        assert_eq!(
            read(&db, &deposit_key(&deployment(), &deposit.id)).await,
            Some(Record::Deposit(deposit.clone()))
        );
        let after_first = status(&db).await;
        assert_eq!(after_first.custody, 407);
        assert_eq!(after_first.claimable, 0);

        // An exact replay lands on the consumed id and mutates nothing.
        seal(&db, 2, std::slice::from_ref(&tx)).await;
        assert_eq!(status(&db).await.custody, 407);

        // A reused id with another event is a conflict: the custody record
        // stays bound to the original event and no custody moves.
        let conflict = deposit_tx(DepositEvent {
            amount: 8,
            ..deposit.clone()
        });
        seal(&db, 3, std::slice::from_ref(&conflict)).await;
        assert_eq!(
            read(&db, &deposit_key(&deployment(), &deposit.id)).await,
            Some(Record::Deposit(deposit))
        );
        assert_eq!(status(&db).await.custody, 407);

        // An account outside the configured identities is rejected with no
        // effect: no custody record, no custody.
        let unknown_event = DepositEvent {
            id: Sha256::hash(&[b"chain-unknown-account"]),
            account: crate::protocol::Wallet::from_seed("stranger", 999).public_key(),
            amount: 1,
        };
        let unknown = deposit_tx(unknown_event.clone());
        seal(&db, 4, std::slice::from_ref(&unknown)).await;
        assert_eq!(
            read(&db, &deposit_key(&deployment(), &unknown_event.id)).await,
            None
        );
        assert_eq!(status(&db).await.custody, 407);
    });
}

#[test]
fn admitted_close_finalizes_at_real_heights() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("finalize"), "finalize").await;
        let txs = [fixture.deposit_tx.clone(), fixture.register_tx.clone()];
        seal(&db, 1, &txs).await;
        assert!(matches!(
            read(&db, &anchor_key(&deployment(), 0)).await,
            Some(Record::Anchor(_))
        ));
        assert!(matches!(
            read(&db, &registration_key(&deployment())).await,
            Some(Record::Registration(_))
        ));
        assert!(matches!(
            read(&db, &deposit_key(&deployment(), &fixture.deposit.id)).await,
            Some(Record::Deposit(_))
        ));

        // The admission deadline (height 11) is a maximum: admission lands at
        // deadline minus one after idle blocks without faulting.
        for height in 2..=9 {
            seal(&db, height, &[]).await;
        }
        seal(&db, 10, std::slice::from_ref(&fixture.admit_tx)).await;
        let batch_id = fixture.result.finalized.batch_id;
        assert_eq!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(super::state::AdmittedRootsResponse::new(
                batch_id,
                fixture.result.roots,
                false,
            )))
        );

        // The close stays pending through the inclusive challenge deadline
        // (height 12) and finalizes at height 13.
        for height in 11..=12 {
            seal(&db, height, &[]).await;
        }
        let pending = status(&db).await;
        assert_eq!(pending.last_finalized, None);

        seal(&db, 13, &[]).await;
        let finalized = status(&db).await;
        assert_eq!(finalized.last_finalized, Some(0));
        assert_eq!(
            finalized.state_root,
            fixture.result.finalized.successor_root
        );
        assert_eq!(finalized.custody, 401);
        assert!(!finalized.hard_faulted);
        assert_eq!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(super::state::AdmittedRootsResponse::new(
                batch_id,
                fixture.result.roots,
                true,
            )))
        );
        assert_eq!(
            read(&db, &claim_roots_key(&deployment(), &batch_id)).await,
            Some(Record::ClaimRoots(super::state::ClaimRootsResponse {
                withdrawal_outputs: fixture.result.roots.withdrawal_outputs,
                change: fixture.result.roots.change,
            }))
        );
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);

        // An exact admission replay after finalization lands on the
        // finalized admitted record: a harmless conflict that mutates
        // nothing, with the effect record already proving the admission.
        seal(&db, 14, std::slice::from_ref(&fixture.admit_tx)).await;
        assert_eq!(status(&db).await.custody, 401);
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted)) if admitted.batch_id == batch_id && admitted.finalized
        ));

        // A conflicting admission for the finalized epoch is rejected with
        // no effect: the admitted record and custody are untouched.
        let mut conflicting = match &fixture.admit_tx {
            SettlementTx::Admit(request) => request.clone(),
            _ => unreachable!(),
        };
        conflicting.predecessor_liability -= 1;
        let conflicting = SettlementTx::Admit(conflicting);
        seal(&db, 15, std::slice::from_ref(&conflicting)).await;
        assert_eq!(status(&db).await.custody, 401);
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted)) if admitted.batch_id == batch_id && admitted.finalized
        ));
    });
}

#[test]
fn proven_challenge_inside_the_window_faults_the_deployment() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("challenge"), "challenge").await;
        seal(
            &db,
            1,
            &[
                fixture.deposit_tx.clone(),
                fixture.register_tx.clone(),
                fixture.admit_tx.clone(),
            ],
        )
        .await;

        let batch_id = fixture.result.finalized.batch_id;
        let evidence = ack_fork(&fixture.result, &fixture.protocol, (2, 3)).encode();
        let challenge = SettlementTx::Challenge(ChallengeRequest {
            batch_id,
            evidence: evidence.clone(),
        });
        seal(&db, 2, std::slice::from_ref(&challenge)).await;
        let faulted = status(&db).await;
        assert!(faulted.hard_faulted);
        assert_eq!(faulted.last_finalized, None);
        let fault = read(&db, &fault_key(&deployment())).await;
        assert!(matches!(
            &fault,
            Some(Record::Fault(super::state::FaultRecord::Faulted(
                HardFaultReasonResponse::ProvenChallenge {
                    kind: ChallengeKind::AckFork,
                    ..
                }
            )))
        ));
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);

        // The exact evidence replays into the one-proven-per-batch guard,
        // distinct valid evidence against the already-challenged close
        // conflicts, and evidence that does not even decode is rejected by
        // the chain: all three leave the fault record untouched.
        seal(&db, 3, std::slice::from_ref(&challenge)).await;
        assert_eq!(read(&db, &fault_key(&deployment())).await, fault);
        let different = SettlementTx::Challenge(ChallengeRequest {
            batch_id,
            evidence: ack_fork(&fixture.result, &fixture.protocol, (4, 5)).encode(),
        });
        seal(&db, 4, std::slice::from_ref(&different)).await;
        assert_eq!(read(&db, &fault_key(&deployment())).await, fault);
        let mut tampered = evidence.to_vec();
        tampered.push(0);
        let tampered = SettlementTx::Challenge(ChallengeRequest {
            batch_id,
            evidence: Bytes::from(tampered),
        });
        seal(&db, 5, std::slice::from_ref(&tampered)).await;
        assert_eq!(read(&db, &fault_key(&deployment())).await, fault);
    });
}

#[test]
fn hard_fault_claims_replay_idempotently() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("hard_fault"), "hard-fault").await;
        seal(
            &db,
            1,
            &[
                fixture.deposit_tx.clone(),
                fixture.register_tx.clone(),
                fixture.admit_tx.clone(),
            ],
        )
        .await;
        let evidence = ack_fork(&fixture.result, &fixture.protocol, (2, 3)).encode();
        let challenge = SettlementTx::Challenge(ChallengeRequest {
            batch_id: fixture.result.finalized.batch_id,
            evidence,
        });
        seal(&db, 2, std::slice::from_ref(&challenge)).await;
        assert!(status(&db).await.hard_faulted);

        // Begin terminal settlement and drain every account and the pending
        // deposit.
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: deployment(),
        });
        let openings = fixture
            .state
            .leaves()
            .iter()
            .map(|leaf| fixture.state.opening(&leaf.account).unwrap())
            .collect::<Vec<_>>();
        let claims = openings
            .iter()
            .map(|opening| {
                SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
                    deployment: deployment(),
                    opening: opening.clone(),
                })
            })
            .collect::<Vec<_>>();
        let mut txs = vec![begin.clone()];
        txs.extend(claims.iter().cloned());
        seal(&db, 3, &txs).await;
        assert!(matches!(
            read(&db, &fault_key(&deployment())).await,
            Some(Record::Fault(super::state::FaultRecord::Settling(_)))
        ));
        for opening in &openings {
            assert!(matches!(
                read(&db, &hard_fault_key(&deployment(), &opening.leaf.account)).await,
                Some(Record::HardFault(_))
            ));
        }
        let drained = status(&db).await;
        let releases = read(
            &db,
            &hard_fault_key(&deployment(), &openings[0].leaf.account),
        )
        .await;

        // Replays land on the fault and release records without mutating
        // state, and a conflicting opening for a consumed position is
        // rejected with the release record untouched.
        let replays = [begin, claims[0].clone()];
        seal(&db, 4, &replays).await;
        assert_eq!(status(&db).await.custody, drained.custody);
        let mut conflicting = openings[0].clone();
        conflicting.leaf.state.balance -= 1;
        let conflicting = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: deployment(),
            opening: conflicting,
        });
        seal(&db, 5, std::slice::from_ref(&conflicting)).await;
        assert_eq!(
            read(
                &db,
                &hard_fault_key(&deployment(), &openings[0].leaf.account)
            )
            .await,
            releases
        );
        assert_eq!(status(&db).await.custody, drained.custody);

        // The stranded deposit refund drains the last custody.
        let refund = SettlementTx::ClaimPendingDeposit(ClaimPendingDepositRequest {
            deployment: deployment(),
            account: fixture.deposit.account.clone(),
        });
        seal(&db, 6, std::slice::from_ref(&refund)).await;
        assert!(matches!(
            read(&db, &refund_key(&deployment(), &fixture.deposit.account)).await,
            Some(Record::Refund(_))
        ));
        assert_eq!(status(&db).await.custody, 0);

        // The exact refund replays after full settlement with the refund
        // record and custody untouched.
        seal(&db, 7, std::slice::from_ref(&refund)).await;
        assert!(matches!(
            read(&db, &refund_key(&deployment(), &fixture.deposit.account)).await,
            Some(Record::Refund(_))
        ));
        assert_eq!(status(&db).await.custody, 0);
    });
}

#[test]
fn expired_registration_faults_the_deployment() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("registration_expiry"), "registration-expiry").await;
        let register = empty_register_tx();
        seal(&db, 1, std::slice::from_ref(&register)).await;
        assert_eq!(registration(&db).await.epoch, 0);

        // The assigned admission deadline (inclusion height 1 plus the
        // ten-block offset) is inclusive: no fault through height 11, and
        // height 12 observes the expiry and faults.
        for height in 2..=11 {
            seal(&db, height, &[]).await;
        }
        assert!(!status(&db).await.hard_faulted);
        seal(&db, 12, &[]).await;
        let faulted = status(&db).await;
        assert!(faulted.hard_faulted);
        assert!(matches!(
            read(&db, &fault_key(&deployment())).await,
            Some(Record::Fault(super::state::FaultRecord::Faulted(
                HardFaultReasonResponse::ExpiredRegistration {
                    epoch: 0,
                    expired_at: 11,
                    ..
                }
            )))
        ));
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
    });
}

#[test]
fn expired_deposit_faults_the_deployment() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("deposit_expiry"), "deposit-expiry").await;
        let account = identities()[0].key.clone();
        let deposit = deposit_tx(DepositEvent {
            id: Sha256::hash(&[b"chain-expiring-deposit"]),
            account: account.clone(),
            amount: 7,
        });
        seal(&db, 1, std::slice::from_ref(&deposit)).await;

        // The inclusion deadline is height 1 plus the configured timeout.
        let timeout = crate::protocol::settlement_config(&Timing::DEFAULT)
            .deposit_inclusion_timeout
            .get();
        for height in 2..=timeout {
            seal(&db, height, &[]).await;
        }
        assert!(!status(&db).await.hard_faulted);
        seal(&db, timeout + 1, &[]).await;
        assert!(status(&db).await.hard_faulted);
        assert!(matches!(
            read(&db, &fault_key(&deployment())).await,
            Some(Record::Fault(super::state::FaultRecord::Faulted(
                HardFaultReasonResponse::ExpiredDeposit {
                    expired_at,
                    ..
                }
            ))) if expired_at == timeout + 1
        ));

        // The stranded deposit refunds after the fault.
        let refund = SettlementTx::ClaimPendingDeposit(ClaimPendingDepositRequest {
            deployment: deployment(),
            account: account.clone(),
        });
        seal(&db, timeout + 2, std::slice::from_ref(&refund)).await;
        assert!(matches!(
            read(&db, &refund_key(&deployment(), &account)).await,
            Some(Record::Refund(_))
        ));
        assert_eq!(status(&db).await.custody, 400);
    });
}

#[test]
fn expired_withdrawal_faults_the_deployment() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("withdrawal_expiry"), "withdrawal-expiry").await;
        let state = genesis_cache();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let request = SignedWithdrawal::sign(
            deployment(),
            state.root().digest,
            Bytes::from_static(b"chain-withdrawal"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            50,
            wallet.signer(),
        );
        let opening = state.opening(&account).unwrap();
        let withdrawal = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: request.clone(),
            openings: vec![opening],
        });
        seal(&db, 1, std::slice::from_ref(&withdrawal)).await;
        assert_eq!(
            read(&db, &withdrawal_key(&deployment(), &account)).await,
            Some(Record::Withdrawal(request))
        );

        // The signed deadline is the absolute height 50.
        for height in 2..=49 {
            seal(&db, height, &[]).await;
        }
        assert!(!status(&db).await.hard_faulted);
        seal(&db, 50, &[]).await;
        assert!(matches!(
            read(&db, &fault_key(&deployment())).await,
            Some(Record::Fault(super::state::FaultRecord::Faulted(
                HardFaultReasonResponse::ExpiredWithdrawal { expired_at: 50, .. }
            )))
        ));
    });
}

#[test]
fn deployment_fault_is_isolated() {
    deterministic::Runner::default().start(|context| async move {
        let configured = two_deployments();
        let alpha = *configured[0].digest();
        let beta = *configured[1].digest();
        let beta_protocol = Protocol::with_signer(
            NonZeroUsize::MIN,
            operator_signer(1),
            operator_ack_signer(1),
        )
        .unwrap();
        let db = open(context.child("isolated"), "isolated").await;
        let state = genesis_cache();

        // Block 1 interleaves both deployments: A queues a signed withdrawal
        // nothing will ever carry (deadline height 6, the expired obligation
        // under test), while B registers and admits its epoch-0 close under
        // the deadlines the chain assigns at this inclusion (11, 12).
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let request = SignedWithdrawal::sign(
            alpha,
            state.root().digest,
            Bytes::from_static(b"isolated-withdrawal"),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            6,
            wallet.signer(),
        );
        let queue = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: request.clone(),
            openings: vec![state.opening(&account).unwrap()],
        });
        let first = close_fixture(
            &beta_protocol,
            0,
            state.leaves().to_vec(),
            b"isolated-beta-0",
            11,
            12,
        );
        seal_with(
            &db,
            1,
            &configured,
            &[
                queue,
                first.deposit_tx.clone(),
                first.register_tx.clone(),
                first.admit_tx.clone(),
            ],
        )
        .await;

        // A's queued withdrawal lives under A's keys alone: B's scope proves
        // the absence.
        assert!(matches!(
            read(&db, &withdrawal_key(&alpha, &account)).await,
            Some(Record::Withdrawal(recorded)) if recorded == request
        ));
        assert_eq!(read(&db, &withdrawal_key(&beta, &account)).await, None);
        assert_eq!(
            read(&db, &deposit_key(&alpha, &first.deposit.id)).await,
            None
        );
        assert!(matches!(
            read(&db, &deposit_key(&beta, &first.deposit.id)).await,
            Some(Record::Deposit(_))
        ));

        // A hard-faults at its withdrawal deadline while B's admitted close
        // is still inside its challenge window: the fault is A's alone.
        for height in 2..=6 {
            seal_with(&db, height, &configured, &[]).await;
        }
        assert!(matches!(
            read(&db, &fault_key(&alpha)).await,
            Some(Record::Fault(super::state::FaultRecord::Faulted(
                HardFaultReasonResponse::ExpiredWithdrawal { expired_at: 6, .. }
            )))
        ));
        assert_eq!(read(&db, &fault_key(&beta)).await, None);

        // A's terminal settlement begins and its first hard-fault claim
        // releases against A's frozen genesis root. The identical opening
        // naming B is effect-free: both deployments configure the same
        // accounts at the same balances, so only the named deployment
        // separates them, and B is not faulted.
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: alpha,
        });
        let claim = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: alpha,
            opening: state.opening(&account).unwrap(),
        });
        let misdirected = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: beta,
            opening: state.opening(&account).unwrap(),
        });
        seal_with(&db, 7, &configured, &[begin, claim, misdirected]).await;
        assert!(matches!(
            read(&db, &hard_fault_key(&alpha, &account)).await,
            Some(Record::HardFault(_))
        ));
        assert_eq!(read(&db, &hard_fault_key(&beta, &account)).await, None);
        let beta_mid = match read(&db, &status_key(&beta)).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected B's status record, found {record:?}"),
        };
        assert!(!beta_mid.hard_faulted);
        assert_eq!(beta_mid.custody, 401);

        // B's epoch 0 finalizes on schedule, untouched by A's fault.
        for height in 8..=13 {
            seal_with(&db, height, &configured, &[]).await;
        }
        assert!(matches!(
            read(&db, &admitted_key(&beta, 0)).await,
            Some(Record::Admitted(admitted)) if admitted.finalized
        ));
        let beta_settled = match read(&db, &status_key(&beta)).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected B's status record, found {record:?}"),
        };
        assert_eq!(beta_settled.last_finalized, Some(0));
        assert_eq!(
            beta_settled.state_root,
            first.result.finalized.successor_root
        );
        assert!(!beta_settled.hard_faulted);

        // THE isolation pin: A's remaining hard-fault claim lands in the
        // very block that opens B's next epoch, and B closes it cleanly.
        let second = close_fixture(
            &beta_protocol,
            1,
            first.successor.clone(),
            b"isolated-beta-1",
            24,
            25,
        );
        let residual = wallets().remove(1);
        let residual_claim = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: alpha,
            opening: state.opening(&residual.public_key()).unwrap(),
        });
        seal_with(
            &db,
            14,
            &configured,
            &[
                residual_claim,
                second.deposit_tx.clone(),
                second.register_tx.clone(),
                second.admit_tx.clone(),
            ],
        )
        .await;
        assert!(matches!(
            read(&db, &hard_fault_key(&alpha, &residual.public_key())).await,
            Some(Record::HardFault(_))
        ));
        for height in 15..=26 {
            seal_with(&db, height, &configured, &[]).await;
        }
        let beta_end = match read(&db, &status_key(&beta)).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected B's status record, found {record:?}"),
        };
        assert_eq!(beta_end.last_finalized, Some(1));
        assert_eq!(beta_end.state_root, second.result.finalized.successor_root);
        assert_eq!(beta_end.custody, 402);
        assert!(!beta_end.hard_faulted);
        assert_eq!(read(&db, &fault_key(&beta)).await, None);
        let alpha_end = match read(&db, &status_key(&alpha)).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected A's status record, found {record:?}"),
        };
        assert!(alpha_end.hard_faulted);
        assert_eq!(alpha_end.last_finalized, None);
        assert_eq!(alpha_end.custody, 200);
    });
}

#[test]
fn unconfigured_deployment_txs_are_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("unconfigured"), "unconfigured").await;
        let foreign = Protocol::with_signer(
            NonZeroUsize::MIN,
            operator_signer(7),
            operator_ack_signer(7),
        )
        .unwrap();

        // A deposit naming an unconfigured deployment is diagnosed typed and
        // rejected effect-free: no custody record under any scope, no
        // custody moved.
        let event = DepositEvent {
            id: Sha256::hash(&[b"unconfigured-deposit"]),
            account: identities()[0].key.clone(),
            amount: 7,
        };
        let deposit = SettlementTx::Deposit(DepositRequest {
            deployment: foreign.deployment(),
            event: event.clone(),
        });
        assert_eq!(
            advise(&db, &deployments(), &deposit).await.unwrap(),
            Advice::Doomed(Reject::UnknownDeployment)
        );
        seal(&db, 1, std::slice::from_ref(&deposit)).await;
        assert_eq!(
            read(&db, &deposit_key(&foreign.deployment(), &event.id)).await,
            None
        );
        assert_eq!(
            read(&db, &deposit_key(&deployment(), &event.id)).await,
            None
        );
        assert_eq!(status(&db).await.custody, 400);

        // A well-signed registration for the unconfigured deployment is
        // rejected the same way: the signature is the foreign operator's own,
        // but the deployment it names is not hosted here.
        let root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: foreign.deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root: root,
            staged_root: root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature: foreign.sign_chain_registration(0, 400, &root, &root, &withdrawals),
        });
        assert_eq!(
            advise(&db, &deployments(), &register).await.unwrap(),
            Advice::Doomed(Reject::UnknownDeployment)
        );
        seal(&db, 2, std::slice::from_ref(&register)).await;
        assert_eq!(
            read(&db, &registration_key(&foreign.deployment())).await,
            None
        );
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);

        // A queued withdrawal signs its deployment, so naming an
        // unconfigured one is derivable and rejected identically.
        let wallet = wallets().remove(0);
        let queue = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: SignedWithdrawal::sign(
                foreign.deployment(),
                genesis_cache().root().digest,
                Bytes::from_static(b"unconfigured-withdrawal"),
                WithdrawalAction::Amount(NonZeroU64::new(1).unwrap()),
                50,
                wallet.signer(),
            ),
            openings: Vec::new(),
        });
        assert_eq!(
            advise(&db, &deployments(), &queue).await.unwrap(),
            Advice::Doomed(Reject::UnknownDeployment)
        );
        seal(&db, 3, std::slice::from_ref(&queue)).await;
        assert_eq!(
            read(
                &db,
                &withdrawal_key(&foreign.deployment(), &wallet.public_key())
            )
            .await,
            None
        );

        // The terminal transitions name their deployment explicitly and are
        // rejected before touching any machine.
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: foreign.deployment(),
        });
        assert_eq!(
            advise(&db, &deployments(), &begin).await.unwrap(),
            Advice::Doomed(Reject::UnknownDeployment)
        );
        seal(&db, 4, std::slice::from_ref(&begin)).await;
        assert_eq!(read(&db, &fault_key(&foreign.deployment())).await, None);
        assert_eq!(read(&db, &fault_key(&deployment())).await, None);
        assert_eq!(status(&db).await.custody, 400);
    });
}

#[test]
fn rejections_are_effect_free() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("rejections"), "rejections").await;

        // A registration with a tampered field fails authentication.
        let mut register = match empty_register_tx() {
            SettlementTx::RegisterEpoch(register) => register,
            _ => unreachable!(),
        };
        register.predecessor_liability = 399;
        let register = SettlementTx::RegisterEpoch(register);

        // A structurally valid claim against an unknown batch is unavailable,
        // not invalid. The claim is assembled over a genesis opening, since
        // only its shape matters before the batch lookup.
        let state = genesis_cache();
        let opening = state.opening(&state.leaves()[0].account).unwrap().proof;
        let mut encoded = BytesMut::new();
        Bytes::from_static(b"chain-claim-destination").write(&mut encoded);
        7_u64.write(&mut encoded);
        opening.write(&mut encoded);
        let claim = WithdrawalClaim::<Digest>::decode_cfg(
            encoded.freeze(),
            &RangeCfg::new(0..=crate::protocol::MAX_DESTINATION_BYTES),
        )
        .expect("the synthesized claim decodes");
        let batch_id = BatchId::new(Sha256::hash(&[b"chain-unknown-batch"]));
        let position = claim.position();
        let claim = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest { batch_id, claim });

        // A challenge against an unknown batch is rejected by the chain.
        let challenge = SettlementTx::Challenge(ChallengeRequest {
            batch_id,
            evidence: Bytes::from_static(&[0]),
        });
        let txs = [register, claim, challenge];
        seal(&db, 1, &txs).await;

        // Every rejection is effect-free: no registration record, no release
        // record, no fault, and untouched custody. The typed reasons live in
        // the advisory dry-run, never in state.
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
        assert_eq!(read(&db, &anchor_key(&deployment(), 0)).await, None);
        assert_eq!(
            read(
                &db,
                &super::state::withdrawal_release_key(&deployment(), &batch_id, position)
            )
            .await,
            None
        );
        assert_eq!(read(&db, &fault_key(&deployment())).await, None);
        assert_eq!(status(&db).await.custody, 400);
    });
}

/// A challenge transaction padded to the maximum evidence bound: the largest
/// decodable settlement transaction, for byte-heavy proposal backlogs.
fn heavy_tx(seed: u8) -> SettlementTx {
    SettlementTx::Challenge(ChallengeRequest {
        batch_id: BatchId::new(Sha256::hash(&[b"chain-heavy-tx".as_slice(), &[seed]])),
        evidence: Bytes::from(vec![seed; MAX_CHALLENGE_BYTES]),
    })
}

#[test]
fn propose_bounds_block_bytes_and_requeues_the_remainder() {
    deterministic::Runner::default().start(|context| async move {
        // A full backlog of maximal transactions exceeds the block byte
        // budget before the transaction-count bound binds.
        let backlog = (0..MAX_BLOCK_TXS)
            .map(|seed| heavy_tx(u8::try_from(seed).unwrap()))
            .collect::<Vec<_>>();
        let bytes = backlog.iter().map(|tx| tx.encode_size()).sum::<usize>();
        assert!(bytes > MAX_BLOCK_BYTES);

        let (actor, mailbox) = ingress::Actor::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(256),
                capacity: NZUsize!(256),
                bytes: NZUsize!(64 * 1024 * 1024),
                seen: NZUsize!(256),
                lease: 5,
            },
        );
        actor.start(commonware_p2p::utils::mocks::inert_channel::<
            ed25519::PublicKey,
        >([]));
        for tx in &backlog {
            assert_eq!(
                mailbox.submit(tx.clone()).await,
                ingress::Submission::Accepted
            );
        }

        let db = open(context.child("db"), "propose-budget").await;
        let leader = ed25519::PrivateKey::from_seed(0).public_key();
        let genesis = Block::genesis(
            leader.clone(),
            chain_id(&deployments()),
            0,
            initial_sync_target::<deterministic::Context>(),
        );
        let mut app: App<Scheme, ingress::Mailbox> = App::new(
            genesis.clone(),
            Timing::DEFAULT,
            deployments(),
            Finalized::default(),
        );
        let block_context = Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader,
            parent: (View::zero(), genesis.digest()),
        };

        // The first proposal drains under the byte budget, so the block fits
        // the p2p frame and clears its own decode bound.
        let first = app
            .propose(
                (context.child("first"), block_context.clone()),
                marshal::ancestry::from_iter([Arc::new(genesis.clone())]),
                db.new_batches().await,
                Input {
                    upstream: (),
                    provider: mailbox.clone(),
                },
            )
            .await
            .expect("first proposal executes")
            .block;
        let aggregate = first
            .transactions
            .iter()
            .map(|tx| tx.encode_size())
            .sum::<usize>();
        assert!(!first.transactions.is_empty());
        assert!(first.transactions.len() < MAX_BLOCK_TXS);
        assert!(aggregate <= MAX_BLOCK_BYTES);
        assert!(first.encode_size() <= MAX_MESSAGE_SIZE as usize);
        assert_eq!(Block::decode_cfg(first.encode(), &()).unwrap(), first);

        // The un-drained transactions stayed queued, so the next proposal
        // carries exactly the remainder in submission order.
        let second = app
            .propose(
                (context.child("second"), block_context),
                marshal::ancestry::from_iter([Arc::new(genesis.clone())]),
                db.new_batches().await,
                Input {
                    upstream: (),
                    provider: mailbox.clone(),
                },
            )
            .await
            .expect("second proposal executes")
            .block;
        assert!(!second.transactions.is_empty());
        let mut combined = first.transactions.clone();
        combined.extend(second.transactions.iter().cloned());
        assert_eq!(combined, backlog);
    });
}

#[test]
fn verify_waits_out_a_future_dated_block() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("db"), "verify-drift").await;
        let leader = ed25519::PrivateKey::from_seed(0).public_key();
        let genesis = Block::genesis(
            leader.clone(),
            chain_id(&deployments()),
            500,
            initial_sync_target::<deterministic::Context>(),
        );
        let mut app: App<Scheme, ingress::Mailbox> = App::new(
            genesis.clone(),
            Timing::DEFAULT,
            deployments(),
            Finalized::default(),
        );
        let block_context = Context {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader,
            parent: (View::zero(), genesis.digest()),
        };

        // A valid empty block dated beyond the drift bound: its roots are the
        // real execution roots at that timestamp, so only the date is ahead.
        let lead = 5_000;
        let timestamp = now(&context)
            .saturating_add(MAX_TIMESTAMP_DRIFT)
            .saturating_add(lead);
        let sealed = execute(
            db.new_batches().await,
            Height::new(1),
            timestamp,
            &Timing::DEFAULT,
            &deployments(),
            &[],
        )
        .await
        .expect("block execution succeeds");
        let block = Block {
            context: block_context.clone(),
            parent: genesis.digest(),
            height: Height::new(1),
            timestamp,
            state_root: sealed.root(),
            ops_root: sealed.ops_root(),
            range: non_empty_range!(sealed.sync_boundary(), sealed.bounds().tip.size),
            transactions: Vec::new(),
        };
        drop(sealed);

        // Verification does not resolve until the local clock catches up to
        // the claimed timestamp minus the drift bound, then votes the block
        // valid. The deterministic runtime drives time through the wait.
        let started = now(&context);
        let verified = app
            .verify(
                (context.child("verify"), block_context.clone()),
                marshal::ancestry::from_iter([Arc::new(block.clone()), Arc::new(genesis.clone())]),
                db.new_batches().await,
            )
            .await;
        assert!(verified.is_some(), "the future-dated block must verify");
        let finished = now(&context);
        assert!(finished >= started + lead, "verification resolved early");
        assert!(finished.saturating_add(MAX_TIMESTAMP_DRIFT) >= timestamp);

        // A block whose timestamp does not strictly exceed its parent's is
        // permanently invalid: no wait, no execution.
        let stale = Block {
            timestamp: genesis.timestamp,
            ..block
        };
        let rejected = app
            .verify(
                (context.child("verify_stale"), block_context),
                marshal::ancestry::from_iter([Arc::new(stale), Arc::new(genesis)]),
                db.new_batches().await,
            )
            .await;
        assert!(rejected.is_none(), "a non-monotonic timestamp must reject");
    });
}

#[test]
fn block_decode_rejects_an_over_budget_encoding() {
    // MAX_BLOCK_TXS maximal transactions clear the per-transaction and count
    // bounds while their aggregate exceeds the block byte budget: exactly the
    // shape the proposal drain can no longer build.
    let mut block = Block::genesis(
        ed25519::PrivateKey::from_seed(0).public_key(),
        deployment(),
        0,
        initial_sync_target::<deterministic::Context>(),
    );
    block.transactions = (0..MAX_BLOCK_TXS)
        .map(|seed| heavy_tx(u8::try_from(seed).unwrap()))
        .collect();
    let aggregate = |block: &Block| {
        block
            .transactions
            .iter()
            .map(|tx| tx.encode_size())
            .sum::<usize>()
    };
    assert!(
        block
            .transactions
            .iter()
            .all(|tx| tx.encode_size() <= MAX_TX_BYTES)
    );
    assert!(aggregate(&block) > MAX_BLOCK_BYTES);
    assert!(matches!(
        Block::decode_cfg(block.encode(), &()),
        Err(CodecError::Invalid(_, _))
    ));

    // Trimming under the budget restores decodability, pinning the rejection
    // to the budget itself.
    while aggregate(&block) > MAX_BLOCK_BYTES {
        block.transactions.pop();
    }
    assert_eq!(Block::decode_cfg(block.encode(), &()).unwrap(), block);
}

#[test]
fn node_read_waits_for_the_finalized_index() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("db"), "node-catchup").await;
        let finalized = Finalized::default();
        let (sender, _) = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
        let mut node = Node::new(deployment(), db.clone(), finalized.clone(), sender);

        // The applied database runs ahead of the still-empty finalized index,
        // and the delayed report closes the gap: the read must wait out the
        // race instead of surfacing it.
        seal(&db, 1, &[]).await;
        let root = db.read().await.root();
        context.child("report").spawn({
            let finalized = finalized.clone();
            move |context| async move {
                context.sleep(Duration::from_millis(100)).await;
                finalized.record(1, Digest::EMPTY, root, 1);
            }
        });
        let verified = node
            .read(&context, &req(Lookup::Status))
            .await
            .expect("the read waits out the empty finalized index");
        assert_eq!(verified.height, 1);
        assert!(matches!(verified.record, Some(Record::Status(_))));

        // The mismatch arm of the same race: a newly applied block leaves the
        // index one root behind until its delayed report lands.
        seal(&db, 2, &[]).await;
        let root = db.read().await.root();
        context.child("report_next").spawn({
            let finalized = finalized.clone();
            move |context| async move {
                context.sleep(Duration::from_millis(100)).await;
                finalized.record(2, Digest::EMPTY, root, 2);
            }
        });
        let verified = node
            .read(&context, &req(Lookup::Status))
            .await
            .expect("the read waits out the lagging finalized index");
        assert_eq!(verified.height, 2);

        // An index that never catches up still fails, within the budget.
        let (sender, _) = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
        let mut stalled = Node::new(
            deployment(),
            open(context.child("stalled"), "node-stalled").await,
            Finalized::default(),
            sender,
        );
        assert!(stalled.read(&context, &req(Lookup::Status)).await.is_err());
    });
}

#[test]
fn recent_read_retries_a_briefly_unreachable_validator() {
    deterministic::Runner::default().start(|context| async move {
        let upstream = std::net::SocketAddr::from(([127, 0, 0, 1], 4_100));
        let served = std::net::SocketAddr::from(([127, 0, 0, 1], 4_101));
        let dead = std::net::SocketAddr::from(([127, 0, 0, 1], 4_102));
        let control = harness::start(&context, upstream, "recent-retry").await;
        control.advance(1).await;

        // The served address answers only after a delay, relaying the query
        // wire protocol to the harness: the first pass reaches no validator
        // and must retry, never settle for an unverified answer.
        context.child("proxy").spawn(move |context| async move {
            context.sleep(Duration::from_millis(300)).await;
            let mut listener = context.bind(served).await.expect("the proxy binds");
            while let Ok((_, mut sink, mut stream)) = listener.accept().await {
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                let Ok(body) =
                    rpc::invoke(&context, upstream, "query", request.method, request.body).await
                else {
                    continue;
                };
                let _ = rpc::send_response(&mut sink, &rpc::Response::Success { body }).await;
            }
        });
        let mut chain = Client::new(
            control.identity(),
            deployment(),
            vec![served],
            context.child("client"),
        )
        .expect("the client accepts one query address");
        let verified = chain
            .recent(&context, &req(Lookup::Status))
            .await
            .expect("the recency shortfall retries until the validator answers");
        assert!(verified.height >= 1);
        assert!(matches!(verified.record, Some(Record::Status(_))));

        // A validator set that never answers still errors, and the error
        // names the failing validator.
        let mut unreachable = Client::new(
            control.identity(),
            deployment(),
            vec![dead],
            context.child("unreachable"),
        )
        .expect("the client accepts one query address");
        let error = unreachable
            .recent(&context, &req(Lookup::Status))
            .await
            .expect_err("no pass can verify a response");
        let message = format!("{error:#}");
        assert!(
            message.contains("no validator served a recent certified read"),
            "{message}"
        );
        assert!(message.contains(&dead.to_string()), "{message}");
    });
}

#[test]
fn recent_read_rotates_past_a_stale_validator() {
    deterministic::Runner::default().start(|context| async move {
        let upstream = std::net::SocketAddr::from(([127, 0, 0, 1], 4_110));
        let stale = std::net::SocketAddr::from(([127, 0, 0, 1], 4_111));
        let control = harness::start(&context, upstream, "recent-stale").await;
        control.advance(1).await;

        // The stale address relays its first response from the harness, then
        // replays those exact bytes forever: an authentic certified read
        // whose block only ages.
        let replay: Arc<Mutex<Option<bytes::Bytes>>> = Arc::default();
        {
            let replay = replay.clone();
            context.child("stale").spawn(move |context| async move {
                let mut listener = context.bind(stale).await.expect("the stale proxy binds");
                while let Ok((_, mut sink, mut stream)) = listener.accept().await {
                    let Ok(request) = rpc::recv_request(&mut stream).await else {
                        continue;
                    };
                    let cached = replay.lock().clone();
                    let body = match cached {
                        Some(body) => body,
                        None => {
                            let Ok(body) = rpc::invoke(
                                &context,
                                upstream,
                                "query",
                                request.method,
                                request.body,
                            )
                            .await
                            else {
                                continue;
                            };
                            *replay.lock() = Some(body.clone());
                            body
                        }
                    };
                    let _ = rpc::send_response(&mut sink, &rpc::Response::Success { body }).await;
                }
            });
        }

        // While the replayed read is fresh, the stale-to-be validator serves
        // it fine. This first read also pins the bytes the proxy replays.
        let mut pinned = Client::new(
            control.identity(),
            deployment(),
            vec![stale],
            context.child("pinned"),
        )
        .expect("the client accepts one query address");
        let first = pinned
            .recent(&context, &req(Lookup::Status))
            .await
            .expect("the replayed read is recent at capture time");

        // Once the local clock outruns the captured timestamp by more than
        // the threshold, the replayed old certificate fails the recency gate
        // with the address and the observed lag named.
        context
            .sleep(Duration::from_millis(RECENCY_THRESHOLD + 1_000))
            .await;
        let error = pinned
            .recent(&context, &req(Lookup::Status))
            .await
            .expect_err("the replayed old certificate must fail the recency gate");
        let message = format!("{error:#}");
        assert!(message.contains(&stale.to_string()), "{message}");
        assert!(message.contains("behind the local clock"), "{message}");

        // A client that also knows the live validator rotates past the stale
        // one and adopts a strictly newer tip.
        let mut chain = Client::new(
            control.identity(),
            deployment(),
            vec![stale, upstream],
            context.child("client"),
        )
        .expect("the client accepts the address list");
        let rotated = chain
            .recent(&context, &req(Lookup::Status))
            .await
            .expect("the client rotates past the stale validator");
        assert!(rotated.height > first.height);
        assert!(rotated.timestamp > first.timestamp);
    });
}

#[test]
fn node_recent_read_detects_a_stalled_tip() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("db"), "node-stall").await;
        let finalized = Finalized::default();
        let (sender, _) = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
        let mut node = Node::new(deployment(), db.clone(), finalized.clone(), sender);

        // The follower applied a block whose timestamp matches the local
        // clock: the tip is live and the read passes.
        seal(&db, 1, &[]).await;
        let root = db.read().await.root();
        finalized.record(1, Digest::EMPTY, root, now(&context));
        node.recent(&context, &req(Lookup::Status))
            .await
            .expect("a live local tip passes the recency gate");

        // The chain stalls: the local clock advances past the threshold with
        // no newer finalization, and the same gate surfaces the stall with
        // the observed lag.
        context
            .sleep(Duration::from_millis(RECENCY_THRESHOLD + 500))
            .await;
        let error = node
            .recent(&context, &req(Lookup::Status))
            .await
            .expect_err("a stalled local tip must be surfaced as stale");
        let message = format!("{error:#}");
        assert!(
            message.contains("the local finalized tip is stale"),
            "{message}"
        );
        assert!(message.contains("behind the local clock"), "{message}");
    });
}

#[test]
fn execution_is_deterministic_across_databases() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let first = open(context.child("determinism_a"), "determinism-a").await;
        let second = open(context.child("determinism_b"), "determinism-b").await;
        let mut blocks: Vec<Vec<SettlementTx>> = vec![vec![
            fixture.deposit_tx.clone(),
            fixture.register_tx.clone(),
            fixture.admit_tx.clone(),
        ]];
        blocks.extend((2..=13).map(|_| Vec::new()));

        for (index, txs) in blocks.iter().enumerate() {
            let height = index as u64 + 1;
            let left = seal(&first, height, txs).await;
            let right = seal(&second, height, txs).await;
            assert_eq!(left, right, "roots diverged at height {height}");
        }
        assert_eq!(status(&first).await, status(&second).await);
        assert_eq!(status(&first).await.last_finalized, Some(0));
    });
}

#[test]
fn idle_deployment_never_faults() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("idle"), "idle").await;

        // Deadlines are absolute heights fixed when an obligation is created,
        // so a deployment with no obligations can idle forever.
        for height in 1..=200 {
            seal(&db, height, &[]).await;
        }
        let idle = status(&db).await;
        assert!(!idle.hard_faulted);
        assert_eq!(idle.last_finalized, None);
        assert_eq!(idle.custody, 400);
        assert_eq!(read(&db, &fault_key(&deployment())).await, None);
    });
}

#[test]
fn registration_deadlines_are_assigned_at_inclusion() {
    deterministic::Runner::default().start(|context| async move {
        // A deployment whose genesis fixes a non-default policy (offset 3,
        // duration 2): the authority for the assignment is the genesis
        // policy, not the compiled defaults.
        let timing = Timing {
            admission_offset: 3,
            challenge_duration: 2,
        };
        let db = open(context.child("assigned"), "assigned").await;
        let register = empty_register_tx();
        seal_at(&db, 1, &timing, &[]).await;
        seal_at(&db, 2, &timing, std::slice::from_ref(&register)).await;

        // Execution assigned the deadlines from the inclusion height (2):
        // admission at inclusion plus the offset, challenge at admission
        // plus the duration, and the anchor derived over exactly that pair.
        let record = match read(&db, &registration_key(&deployment())).await {
            Some(Record::Registration(record)) => record,
            record => panic!("expected the registration record, found {record:?}"),
        };
        assert_eq!(record.epoch, 0);
        assert_eq!(record.admission_deadline, 5);
        assert_eq!(record.challenge_deadline, 7);
        let context = crate::protocol::epoch_context_at(
            deployment(),
            crate::protocol::operator_key(),
            0,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            400,
            5,
            7,
        )
        .unwrap();
        assert_eq!(&record.anchor, context.payment().anchor());
        assert_eq!(
            read(&db, &anchor_key(&deployment(), 0)).await,
            Some(Record::Anchor(record.anchor))
        );
    });
}

#[test]
fn early_admission_is_accepted() {
    deterministic::Runner::default().start(|context| async move {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();

        // The registration at height 1 is assigned the admission deadline at
        // height 11 (the genesis admission offset past inclusion). The
        // deadline is only an upper bound: the certified close is admitted
        // at height 3, eight blocks before it.
        let epoch = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"chain-early-admission",
            11,
            12,
        );
        let db = open(context.child("early"), "early").await;
        seal(
            &db,
            1,
            &[epoch.deposit_tx.clone(), epoch.register_tx.clone()],
        )
        .await;
        seal(&db, 2, &[]).await;
        seal(&db, 3, std::slice::from_ref(&epoch.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted)) if !admitted.finalized
        ));

        // The challenge window still runs its real blocks to the assigned
        // absolute deadline (height 12): the close stays pending through it
        // and finalizes at height 13, with the admission obligation having
        // completed well before its deadline could expire.
        for height in 4..=12 {
            seal(&db, height, &[]).await;
        }
        assert_eq!(status(&db).await.last_finalized, None);
        seal(&db, 13, &[]).await;
        let finalized = status(&db).await;
        assert_eq!(finalized.last_finalized, Some(0));
        assert_eq!(finalized.height, 13);
        assert!(!finalized.hard_faulted);
    });
}

#[test]
fn back_to_back_early_epochs() {
    deterministic::Runner::default().start(|context| async move {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let db = open(context.child("cadence"), "cadence").await;

        // A genesis policy with a one-block admission offset, so the chain
        // assigns tight windows at every inclusion.
        let timing = Timing {
            admission_offset: 1,
            challenge_duration: 1,
        };

        // Epoch 0 registers, admits, and certifies in one block at height 1:
        // the assigned admission deadline is height 2 and its challenge
        // window (through height 3) elapses at height 4.
        let first = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"chain-cadence-0",
            2,
            3,
        );
        seal_at(
            &db,
            1,
            &timing,
            &[
                first.deposit_tx.clone(),
                first.register_tx.clone(),
                first.admit_tx.clone(),
            ],
        )
        .await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted)) if !admitted.finalized
        ));
        seal_at(&db, 2, &timing, &[]).await;
        seal_at(&db, 3, &timing, &[]).await;

        // Epoch 1 is accepted in the very block that finalizes epoch 0, and
        // its assigned window anchors at that inclusion (heights 5 and 6):
        // fast cadence is bounded only by certification, never by a grid.
        let second = close_fixture(
            &protocol,
            1,
            first.successor.clone(),
            b"chain-cadence-1",
            5,
            6,
        );
        seal_at(
            &db,
            4,
            &timing,
            &[
                second.deposit_tx.clone(),
                second.register_tx.clone(),
                second.admit_tx.clone(),
            ],
        )
        .await;
        assert_eq!(status(&db).await.last_finalized, Some(0));
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 1)).await,
            Some(Record::Admitted(admitted)) if !admitted.finalized
        ));
        for height in 5..=7 {
            seal_at(&db, height, &timing, &[]).await;
        }
        let settled = status(&db).await;
        assert_eq!(settled.last_finalized, Some(1));
        assert_eq!(settled.state_root, second.result.finalized.successor_root);
        assert_eq!(settled.custody, 402);
        assert!(!settled.hard_faulted);
    });
}

// --- light client unit tests ---------------------------------------------

/// Builds a certified read over `db` for `request`, signed by the first
/// quorum of `schemes` over a block committing the database's roots.
async fn certified_read(
    db: &Database<deterministic::Context>,
    schemes: &[Scheme],
    leader: ed25519::PublicKey,
    height: u64,
    transactions: Vec<SettlementTx>,
    request: &ReadRequest,
) -> (CertifiedRead, Block) {
    let batch = db.new_batches().await;
    let sealed = execute(
        batch,
        Height::new(height),
        height,
        &Timing::DEFAULT,
        &deployments(),
        &transactions,
    )
    .await
    .expect("block execution succeeds");
    let block = Block {
        context: Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader,
            parent: (View::zero(), Digest::EMPTY),
        },
        parent: Digest::EMPTY,
        height: Height::new(height),
        timestamp: height,
        state_root: sealed.root(),
        ops_root: sealed.ops_root(),
        range: non_empty_range!(sealed.sync_boundary(), sealed.bounds().tip.size),
        transactions,
    };
    db.apply(sealed).await;

    let proposal = Proposal {
        round: block.context.round,
        parent: View::zero(),
        payload: block.digest(),
    };
    let finalizes = schemes
        .iter()
        .take(3)
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("mock scheme signs"))
        .collect::<Vec<_>>();
    let finalization = Finalization::from_finalizes(
        &schemes[0],
        NonEmpty::try_new(finalizes.iter()).expect("quorum is non-empty"),
        &Sequential,
    )
    .expect("mock quorum assembles");

    let key = request.key();
    let guard = db.read().await;
    let proof = match guard.get(&key).await.expect("state read succeeds") {
        Some(record) => query::ReadProof::Present {
            proof: guard
                .key_value_proof(key)
                .await
                .expect("present key proves"),
            record,
        },
        None => query::ReadProof::Absent {
            proof: guard
                .exclusion_proof(&key)
                .await
                .expect("absent key proves"),
        },
    };
    (
        CertifiedRead {
            finalization: finalization.encode(),
            block: block.encode(),
            proof,
        },
        block,
    )
}

#[test]
fn light_client_verifies_certified_reads() {
    deterministic::Runner::default().start(|context| async move {
        let mut rng = test_rng();
        let SchemeFixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        let db = open(context.child("light"), "light").await;
        let account = identities()[0].key.clone();
        let deposit = DepositEvent {
            id: Sha256::hash(&[b"light-client-deposit"]),
            account,
            amount: 7,
        };
        let tx = deposit_tx(deposit.clone());

        // A present record verifies with its value.
        let request = req(Lookup::Deposit { id: deposit.id });
        let (response, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            1,
            vec![tx.clone()],
            &request,
        )
        .await;
        let verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &request,
            &response,
        )
        .expect("valid response verifies");
        assert_eq!(verified.height, 1);
        assert_eq!(verified.record, Some(Record::Deposit(deposit)));

        // A verified absence proves the key holds nothing: epoch 7 was never
        // registered.
        let absent = req(Lookup::Anchor { epoch: 7 });
        let (absence, _) = certified_read(
            &db,
            &schemes,
            participants[0].clone(),
            2,
            Vec::new(),
            &absent,
        )
        .await;
        let verified = light::verify_read::<deterministic::Context, Scheme>(
            &mut rng,
            &schemes[0],
            &absent,
            &absence,
        )
        .expect("valid absence verifies");
        assert_eq!(verified.height, 2);
        assert_eq!(verified.record, None);

        // The wrong committee identity rejects the certificate.
        let SchemeFixture {
            schemes: other_schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &other_schemes[0],
                &request,
                &response,
            ),
            Err(light::Error::Certificate)
        ));

        // Tampered block bytes break the certified commitment.
        let mut tampered = response.clone();
        let mut bytes = tampered.block.to_vec();
        bytes[0] ^= 1;
        tampered.block = Bytes::from(bytes);
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &request,
                &tampered,
            ),
            Err(light::Error::Commitment)
        ));

        // A proof against the wrong root fails even under a valid
        // certificate: the absence response at height 2 certifies a different
        // root than the proof taken at height 1.
        let mut wrong_root = absence;
        wrong_root.proof = response.proof.clone();
        assert!(matches!(
            light::verify_read::<deterministic::Context, Scheme>(
                &mut rng,
                &schemes[0],
                &request,
                &wrong_root,
            ),
            Err(light::Error::Proof)
        ));

        // The monotonic gate accepts advancing heights and rejects a stale
        // replay.
        let mut latest = light::Latest::default();
        latest.observe(1).expect("first height is accepted");
        latest.observe(2).expect("advancing height is accepted");
        assert!(matches!(
            latest.observe(1),
            Err(light::Error::Stale {
                height: 1,
                accepted: 2
            })
        ));
    });
}

#[test]
fn recency_passes_exactly_at_the_threshold() {
    let verified = light::Verified {
        height: 3,
        timestamp: 1_000,
        record: None,
    };

    // A lag exactly at the threshold passes, one millisecond beyond it is
    // rejected with the observed lag named, and a timestamp ahead of the
    // local clock (bounded proposer drift) never reads as stale.
    assert!(light::recent(&verified, 1_000 + RECENCY_THRESHOLD, RECENCY_THRESHOLD).is_ok());
    match light::recent(&verified, 1_001 + RECENCY_THRESHOLD, RECENCY_THRESHOLD) {
        Err(light::Error::Lagging { lag, bound }) => {
            assert_eq!(lag, RECENCY_THRESHOLD + 1);
            assert_eq!(bound, RECENCY_THRESHOLD);
        }
        other => panic!("expected the lagging rejection, found {other:?}"),
    }
    assert!(light::recent(&verified, 0, RECENCY_THRESHOLD).is_ok());
}

// --- glue::simulate end-to-end test -------------------------------------

const NAMESPACE: &[u8] = b"terminal_chain_e2e";
const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1024));

type Scheme = MockScheme<ed25519::PublicKey>;

/// State-sync source that never answers: no validator syncs in this test.
#[derive(Clone)]
struct NoopResolver;

impl QmdbSource for NoopResolver {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Operation<mmr::Family, StateKey, Record>;
    type Error = Infallible;

    fn serve<'a>(
        &'a self,
        _request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error>,
    > + Send
    + 'a {
        std::future::pending()
    }
}

impl AttachableResolver<Qmdb<deterministic::Context>> for NoopResolver {
    async fn attach_database(&self, _db: Shared<Qmdb<deterministic::Context>>) {}
}

/// Type-erased state reader so validator state does not name actor types.
type StateReader =
    Arc<dyn Fn(StateKey) -> Pin<Box<dyn Future<Output = Option<Record>> + Send>> + Send + Sync>;

/// Shared slot for the RPC client's verdict, written once by validator 0's
/// client task.
type ClientResult = Arc<Mutex<Option<Result<(), String>>>>;

/// Per-operator driver verdicts, folded into one [`ClientResult`].
type Verdicts = Arc<Mutex<Vec<Option<Result<(), String>>>>>;

/// Per-validator state inspected by the exit condition and property. The
/// mock-certified engines use the default scheme parameter, and the
/// walkthrough engine instantiates it at the production threshold scheme.
#[derive(Clone)]
struct State<S: CertScheme<Digest> = Scheme> {
    marshal: marshal::core::Mailbox<S, Standard<Block>>,
    reader: StateReader,
    finalized: Finalized,
    client: ClientResult,
}

impl<S: CertScheme<Digest>> ProcessedHeight for State<S> {
    async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}

/// Four validators finalizing the deposit -> register -> admit -> finalize
/// sequence submitted through validator 0's query server and gossiped by the
/// ingress actors.
#[derive(Clone)]
struct Engine {
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<Scheme>,
    finalized: Vec<Finalized>,
    client: ClientResult,
    expected_root: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
    deposit_id: Digest,
}

impl Engine {
    fn new(n: u32) -> Self {
        let mut rng = test_rng();
        let SchemeFixture {
            participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, n);

        // The client rebuilds the fixture with the deadlines the chain
        // assigns at inclusion. The settled root and deposit id are
        // deadline-independent, so a throwaway fixture pins the expectations.
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let epoch = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"chain-e2e-deposit",
            2,
            3,
        );
        let finalized = (0..n as usize).map(|_| Finalized::default()).collect();
        Self {
            participants,
            schemes,
            finalized,
            client: ClientResult::default(),
            expected_root: epoch.result.finalized.successor_root,
            deposit_id: epoch.deposit.id,
        }
    }

    /// Query server address for one validator.
    fn query_address(index: usize) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 6_000 + index as u16))
    }
}

impl EngineDefinition for Engine {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = State;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (0, TEST_QUOTA), // votes
            (1, TEST_QUOTA), // certificates
            (2, TEST_QUOTA), // resolver
            (3, TEST_QUOTA), // backfill
            (4, TEST_QUOTA), // broadcast
            (5, TEST_QUOTA), // settlement transactions
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            delayed: _,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;

        let scheme = self.schemes[index].clone();
        let partition_prefix = format!("validator-{index}");
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let db_config = config(&partition_prefix, &context);

        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let settlement_tx_network = channels.next().unwrap();

        // Marshal resolver.
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(100),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill_network,
        );

        // Buffered broadcast engine.
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: NZUsize!(100),
                deque_size: 10,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            },
        );
        broadcast_engine.start(broadcast_network);

        // Prunable archives backing marshal.
        let archive_config = |name: &str| prunable::Config {
            translator: TwoCap,
            key_partition: format!("{partition_prefix}-{name}-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-{name}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(10),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        };
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config("finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks =
            prunable::Archive::init(context.child("finalized_blocks"), archive_config("blocks"))
                .await
                .expect("failed to initialize blocks archive");

        // Genesis block shared by every validator, dated at the simulated
        // deployment start.
        let genesis_block = Block::genesis(
            self.participants[0].clone(),
            chain_id(&deployments()),
            0,
            initial_sync_target::<deterministic::Context>(),
        );

        let startup = context.child("stateful_startup");
        let plan = SyncPlan::init(&startup, partition_prefix.clone()).await;
        let _ = plan.should_state_sync(false);
        let provider = ConstantProvider::new(scheme.clone());

        // Marshal actor.
        let (marshal_actor, marshal_mailbox, floor) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: provider.clone(),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: plan.marshal_start(genesis_block.clone()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(100),
                    view_retention: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;

        // Transaction ingress: peers gossip settlement transactions and
        // proposals borrow from the queue.
        let (ingress_actor, ingress_mailbox) = ingress::Actor::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(100),
                capacity: NZUsize!(1_024),
                bytes: NZUsize!(64 * 1024 * 1024),
                seen: NZUsize!(4_096),
                lease: 5,
            },
        );
        ingress_actor.start(settlement_tx_network);

        // Stateful actor wrapping the settlement application. No validator
        // state-syncs in this test, so the resolver is a no-op.
        let finalized = self.finalized[index].clone();
        let application: App<Scheme, ingress::Mailbox> = App::new(
            genesis_block.clone(),
            Timing::DEFAULT,
            deployments(),
            finalized.clone(),
        );
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                provider: ingress_mailbox.clone(),
                marshal: (marshal_mailbox.clone(), floor),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: NoopResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
                prune_config: None,
            },
        );

        // Type-erased state reader for the end-of-run property.
        let reader_mailbox = stateful_mailbox.clone();
        let reader: StateReader = Arc::new(move |key: StateKey| {
            let mailbox = reader_mailbox.clone();
            Box::pin(async move {
                let databases = mailbox.subscribe_databases().await;
                let guard = databases.read().await;
                guard.get(&key).await.expect("state read must succeed")
            })
        });

        // Deferred wrapper and marshal startup. The ingress mailbox rides the
        // reporter stream so the queue retires included transactions.
        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let marshal_reporters = MonitorReporter::new(
            public_key.clone(),
            monitor,
            Reporters::from((stateful_mailbox.clone(), ingress_mailbox.clone())),
        );
        marshal_actor.start(marshal_reporters, buffer, resolver);
        stateful_actor.start();

        // Certified query server over the applied database.
        let db = stateful_mailbox.subscribe_databases().await;
        query::start(
            context.child("query"),
            query::Config {
                address: Self::query_address(index),
                deployments: deployments(),
                db,
                finalized: finalized.clone(),
                marshal: marshal_mailbox.clone(),
                ingress: ingress_mailbox,
                sealer: None,
            },
        );

        // Validator 0 drives the RPC round trip: submit over the query
        // server, wait for certified finalization, and verify every read
        // through the light client.
        if index == 0 {
            let verdict = self.client.clone();
            let scheme_for_client = scheme.clone();
            let expected_root = self.expected_root;
            context.child("client").spawn(move |context| async move {
                let result = client(
                    context,
                    scheme_for_client,
                    Self::query_address(0),
                    expected_root,
                )
                .await
                .map_err(|error| format!("{error:#}"));
                *verdict.lock() = Some(result);
            });
        }

        // Simplex engine.
        let engine = simplex::Engine::new(
            context,
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: oracle.control(public_key.clone()),
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox.clone(),
                strategy: Sequential,
                partition: format!("{partition_prefix}-simplex"),
                mailbox_size: NZUsize!(3),
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Genesis(genesis_block.digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_millis(500),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: simplex::SkipBudget::Participants,
                },
                fetch_timeout: Duration::from_secs(2),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );
        let handle = engine.start(vote_network, certificate_network, resolver_network);

        (
            handle,
            State {
                marshal: marshal_mailbox,
                reader,
                finalized,
                client: self.client.clone(),
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

/// Submits one certified read and decodes the response.
async fn certified(
    context: &deterministic::Context,
    address: std::net::SocketAddr,
    request: &ReadRequest,
) -> anyhow::Result<ReadResponse> {
    let body = crate::rpc::invoke(
        context,
        address,
        "query",
        query::METHOD_READ,
        request.encode(),
    )
    .await?;
    Ok(ReadResponse::decode_cfg(body, &())?)
}

/// Polls certified reads for `request` until one is available and verifies
/// it, returning the verified read and the raw response.
async fn verified_read(
    context: &mut deterministic::Context,
    scheme: &Scheme,
    address: std::net::SocketAddr,
    request: &ReadRequest,
) -> anyhow::Result<(light::Verified, CertifiedRead)> {
    loop {
        match certified(context, address, request).await {
            Ok(ReadResponse::Certified(response)) => {
                let verified = light::verify_read::<deterministic::Context, Scheme>(
                    context, scheme, request, &response,
                )
                .map_err(|error| anyhow::anyhow!("verification failed: {error}"))?;
                return Ok((verified, response));
            }

            // The server is still binding, or no snapshot is servable yet.
            Ok(ReadResponse::Unavailable) | Err(_) => {
                context.sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// Submits one transaction, retrying while the server binds, and returns the
/// advisory answer once the server answers.
async fn submit(
    context: &deterministic::Context,
    address: std::net::SocketAddr,
    tx: &SettlementTx,
) -> anyhow::Result<query::Submitted> {
    loop {
        let request = crate::rpc::Request {
            method: query::METHOD_SUBMIT_TX,
            body: tx.encode(),
        };
        match crate::rpc::call(context, address, &request).await {
            Ok(crate::rpc::Response::Success { body }) => {
                return Ok(query::Submitted::decode_cfg(body, &())?);
            }
            Ok(crate::rpc::Response::Error { error }) => {
                anyhow::bail!("submission rejected: {}", String::from_utf8_lossy(&error));
            }
            Err(_) => context.sleep(Duration::from_millis(200)).await,
        }
    }
}

/// Submits one transaction and waits for a certified read proving its
/// `effect` record present, returning the height it was proven at.
async fn submit_effective(
    context: &mut deterministic::Context,
    scheme: &Scheme,
    address: std::net::SocketAddr,
    tx: &SettlementTx,
    effect: &ReadRequest,
    latest: &mut light::Latest,
) -> anyhow::Result<u64> {
    let submitted = submit(context, address, tx).await?;
    anyhow::ensure!(
        matches!(
            submitted.admission,
            ingress::Submission::Accepted | ingress::Submission::Duplicate
        ),
        "submission was not admitted: {submitted:?}"
    );
    loop {
        let (verified, _) = verified_read(context, scheme, address, effect).await?;
        latest
            .observe(verified.height)
            .map_err(|error| anyhow::anyhow!("effect read regressed: {error}"))?;
        if verified.record.is_some() {
            return Ok(verified.height);
        }
        context.sleep(Duration::from_millis(200)).await;
    }
}

/// The RPC round trip driven against validator 0's query server.
async fn client(
    mut context: deterministic::Context,
    scheme: Scheme,
    address: std::net::SocketAddr,
    expected_root: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
) -> anyhow::Result<()> {
    // The deposit carries no deadline, so it is submitted first: the
    // boundary-only registration commits its root. Registration and
    // admission depend on their predecessors, so each waits for the prior
    // certified effect record (gossip does not preserve order).
    let protocol = Protocol::new(NonZeroUsize::MIN)?;
    let state = genesis_cache();
    let (deposit, deposit_tx, register_tx) =
        fixture_boundary(&protocol, 0, state.leaves(), b"chain-e2e-deposit");
    let mut latest = light::Latest::default();
    submit_effective(
        &mut context,
        &scheme,
        address,
        &deposit_tx,
        &req(Lookup::Deposit { id: deposit.id }),
        &mut latest,
    )
    .await?;
    submit_effective(
        &mut context,
        &scheme,
        address,
        &register_tx,
        &req(Lookup::Registration),
        &mut latest,
    )
    .await?;

    // Execution assigned the deadlines at the registration's inclusion
    // height, so the close is built only after the certified registration
    // read reveals them: the operator's read-back flow.
    let (verified, _) =
        verified_read(&mut context, &scheme, address, &req(Lookup::Registration)).await?;
    let Some(Record::Registration(record)) = verified.record else {
        anyhow::bail!("the registered epoch left no certified record");
    };
    anyhow::ensure!(record.epoch == 0, "the certified record is not epoch 0");
    let epoch = close_fixture(
        &protocol,
        0,
        state.leaves().to_vec(),
        b"chain-e2e-deposit",
        record.admission_deadline,
        record.challenge_deadline,
    );
    anyhow::ensure!(
        epoch.deposit_tx == deposit_tx && epoch.register_tx == register_tx,
        "the fixture boundary diverged from the submitted transactions"
    );
    anyhow::ensure!(
        epoch.result.finalized.successor_root == expected_root,
        "the fixture root diverged from the expectation"
    );
    submit_effective(
        &mut context,
        &scheme,
        address,
        &epoch.admit_tx,
        &req(Lookup::Admitted { epoch: 0 }),
        &mut latest,
    )
    .await?;

    // Wait for a certified status read proving epoch zero finalized with the
    // expected root.
    let (settled_height, first) = loop {
        let (verified, response) =
            verified_read(&mut context, &scheme, address, &req(Lookup::Status)).await?;
        latest
            .observe(verified.height)
            .map_err(|error| anyhow::anyhow!("status read regressed: {error}"))?;
        let Some(Record::Status(status)) = verified.record else {
            anyhow::bail!("status read returned no record");
        };
        if status.hard_faulted {
            anyhow::bail!("the deployment hard-faulted");
        }
        if status.last_finalized == Some(0) {
            anyhow::ensure!(
                status.state_root == expected_root,
                "finalized state root diverged from the close"
            );
            break (verified.height, response);
        }
        context.sleep(Duration::from_millis(200)).await;
    };

    // The included deposit's record is certified present, and an
    // unregistered epoch's anchor is certified absent.
    let deposit_request = req(Lookup::Deposit {
        id: Sha256::hash(&[b"chain-e2e-deposit"]),
    });
    let (verified, _) = verified_read(&mut context, &scheme, address, &deposit_request).await?;
    anyhow::ensure!(
        matches!(verified.record, Some(Record::Deposit(_))),
        "deposit record was not certified"
    );
    let absent_request = req(Lookup::Anchor { epoch: 7 });
    let (verified, _) = verified_read(&mut context, &scheme, address, &absent_request).await?;
    anyhow::ensure!(
        verified.record.is_none(),
        "unregistered epoch anchor was certified present"
    );

    // A stale-certificate replay verifies (it is authentic for its height)
    // but the monotonic gate rejects it once a later read was accepted.
    let fresh_height = loop {
        let (verified, _) =
            verified_read(&mut context, &scheme, address, &req(Lookup::Status)).await?;
        if verified.height > settled_height {
            break verified.height;
        }
        context.sleep(Duration::from_millis(200)).await;
    };
    latest
        .observe(fresh_height)
        .map_err(|error| anyhow::anyhow!("fresh read regressed: {error}"))?;
    let replayed = light::verify_read::<deterministic::Context, Scheme>(
        &mut context,
        &scheme,
        &req(Lookup::Status),
        &first,
    )
    .map_err(|error| anyhow::anyhow!("stale replay failed verification: {error}"))?;
    anyhow::ensure!(
        matches!(
            latest.observe(replayed.height),
            Err(light::Error::Stale { .. })
        ),
        "stale replay was not detected"
    );
    Ok(())
}

/// Every validator settled epoch zero: the deposit is recorded, the close
/// finalized, and custody reflects the deposit.
#[derive(Clone)]
struct Settled {
    expected_root: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
    deposit_id: Digest,
}

impl Property<ed25519::PublicKey, State> for Settled {
    fn name(&self) -> &str {
        "settlement finalized epoch zero"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let status = match (state.reader)(status_key(&deployment())).await {
                    Some(Record::Status(status)) => status,
                    record => return Err(format!("expected a status record, found {record:?}")),
                };
                if status.last_finalized != Some(0) {
                    return Err(format!(
                        "epoch zero did not finalize: {:?}",
                        status.last_finalized
                    ));
                }
                if status.state_root != self.expected_root {
                    return Err("finalized state root diverged from the close".into());
                }
                if status.custody != 401 || status.claimable != 0 || status.hard_faulted {
                    return Err(format!(
                        "unexpected settled balances: custody {} claimable {} faulted {}",
                        status.custody, status.claimable, status.hard_faulted
                    ));
                }
                if !matches!(
                    (state.reader)(deposit_key(&deployment(), &self.deposit_id)).await,
                    Some(Record::Deposit(_))
                ) {
                    return Err("the settled deposit record is missing".into());
                }
                if state.finalized.latest().is_none() {
                    return Err("the finalized index is empty".into());
                }
            }
            Ok(())
        })
    }
}

/// Block timestamps are strictly monotonic across the finalized run.
#[derive(Clone)]
struct Monotonic;

impl<S: CertScheme<Digest>> Property<ed25519::PublicKey, State<S>> for Monotonic {
    fn name(&self) -> &str {
        "block timestamps are strictly monotonic"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State<S>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let processed = state.processed_height().await;
                let mut compared = 0_u64;
                let mut previous = None;
                for height in 0..=processed {
                    // Marshal may have pruned early heights, so compare only
                    // consecutive retained blocks and require enough
                    // comparisons for the property to be non-vacuous.
                    let Some(block) = state.marshal.get_block(Height::new(height)).await else {
                        previous = None;
                        continue;
                    };
                    if let Some(previous) = previous
                        && block.timestamp <= previous
                    {
                        return Err(format!(
                            "timestamp did not advance at height {height}: {} <= {previous}",
                            block.timestamp
                        ));
                    }
                    previous = Some(block.timestamp);
                    compared += 1;
                }
                if compared < 10 {
                    return Err(format!("only {compared} finalized blocks were comparable"));
                }
            }
            Ok(())
        })
    }
}

/// Exit once the RPC client finished and every validator processed `height`.
#[derive(Clone)]
struct ClientDoneAt {
    height: u64,
}

impl ExitCondition<ed25519::PublicKey, State> for ClientDoneAt {
    fn name(&self) -> &str {
        "client done and heights processed"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            if !states.iter().any(|state| state.client.lock().is_some()) {
                return Ok(false);
            }
            let mut processed = 0;
            for state in states {
                if state.processed_height().await >= self.height {
                    processed += 1;
                }
            }
            Ok(processed >= target_count)
        })
    }
}

/// The RPC client completed the certified round trip successfully.
#[derive(Clone)]
struct ClientSucceeded;

impl<S: CertScheme<Digest>> Property<ed25519::PublicKey, State<S>> for ClientSucceeded {
    fn name(&self) -> &str {
        "query round trip verified"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State<S>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(state) = states.first() else {
                return Err("no validator states".into());
            };
            match state.client.lock().clone() {
                Some(Ok(())) => Ok(()),
                Some(Err(error)) => Err(format!("client failed: {error}")),
                None => Err("client never finished".into()),
            }
        })
    }
}

#[test]
fn chain_finalizes_settlement_epoch() {
    let engine = Engine::new(4);
    let expected_root = engine.expected_root;
    let deposit_id = engine.deposit_id;
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(ClientDoneAt { height: 35 })
        .property(Settled {
            expected_root,
            deposit_id,
        })
        .property(Monotonic)
        .property(ClientSucceeded)
        .run()
        .unwrap();
}

// --- distributed certification end-to-end tests ---------------------------

/// The deposit label shared by the distributed fixture and its driver.
const DISTRIBUTED_DEPOSIT: &[u8] = b"distributed-e2e-deposit";
const DISTRIBUTED_DEPOSIT_1: &[u8] = b"distributed-e2e-deposit-1";

/// The deposit label of one distributed epoch.
fn deposit_label(epoch: u64) -> &'static [u8] {
    match epoch {
        0 => DISTRIBUTED_DEPOSIT,
        1 => DISTRIBUTED_DEPOSIT_1,
        epoch => panic!("the distributed engine closes at most two epochs, not {epoch}"),
    }
}

/// How a validator's query server misbehaves for evidence requests.
#[derive(Clone, Copy, Debug)]
enum Impairment {
    /// Every request is answered with undecodable bytes.
    Garbage,
    /// Every connection is accepted and never answered.
    Silent,
}

/// A query server standing in for one validator's: it accepts every
/// connection (counting each in `accepts`) and answers as `impairment`
/// dictates, so a co-holder fetching an interval from it must rotate past
/// it. The validator's sealer keeps running (its mailbox is held here for
/// the server's lifetime), so only the evidence it serves is broken, never
/// its sealing or voting.
fn impaired_query(
    context: deterministic::Context,
    address: std::net::SocketAddr,
    impairment: Impairment,
    sealer: Option<da::Mailbox>,
    accepts: Arc<AtomicUsize>,
) {
    context.spawn(move |context| async move {
        let _sealer = sealer;
        let mut listener = context
            .bind(address)
            .await
            .expect("the impaired query server binds");
        loop {
            let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                return;
            };
            accepts.fetch_add(1, Ordering::Relaxed);
            context.child("connection").spawn(move |_| async move {
                if rpc::recv_request(&mut stream).await.is_err() {
                    return;
                }
                match impairment {
                    Impairment::Garbage => {
                        let response = rpc::Response::Success {
                            body: Bytes::from_static(&[0xff]),
                        };
                        let _ = rpc::send_response(&mut sink, &response).await;
                    }
                    Impairment::Silent => std::future::pending::<()>().await,
                }
            });
        }
    });
}

/// The genesis validator list of the distributed engine: validator `i`'s
/// dealt clearing key served at its query address.
fn validator_entries() -> Vec<ValidatorEntry> {
    let committee = committee().unwrap();
    (0..4)
        .map(|index| ValidatorEntry {
            clearing: committee.members()[usize::from(dealt_participant(index).unwrap())],
            query: Engine::query_address(index),
        })
        .collect()
}

/// Settlement transaction sender type on the simulated network.
type TxSender = commonware_p2p::simulated::Sender<ed25519::PublicKey, deterministic::Context>;

/// Four validators plus the operator as a registered p2p secondary: the
/// operator drives a real distributed close over the settlement DA channel
/// (dissemination, sealing, votes, exact-quorum certificate) and submits
/// the certified admission over the transaction channel, completing against
/// its own followed state.
#[derive(Clone)]
struct Distributed {
    /// Four consensus validators, then the operator's network identity.
    participants: Vec<ed25519::PublicKey>,
    schemes: Vec<Scheme>,
    finalized: Vec<Finalized>,
    driver: ClientResult,
    /// Validator indices that run no sealer and so never vote.
    silent: std::collections::BTreeSet<usize>,
    /// Connections the impaired query server accepted, so a rotation test
    /// proves the fetch actually met the impairment.
    impaired_accepts: Arc<AtomicUsize>,
    /// Per epoch, the validator the operator leaves out of its deals: a
    /// validator that misses that close.
    undealt: std::collections::BTreeMap<u64, usize>,
    /// The validator whose query server misbehaves for evidence, and how.
    impaired: Option<(usize, Impairment)>,
    /// Epochs the driver closes back to back.
    epochs: u64,
    /// The validator that missed epoch 0 and fetches every retained interval
    /// before sealing epoch 1, whose fetched records the driver compares
    /// against its co-holders'.
    fetcher: Option<usize>,
    /// Whether the driver expects the registration to expire into the
    /// deadline fault instead of certifying.
    expect_fault: bool,
    /// The state root the last closed epoch settles.
    expected_root: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
    deposit_id: Digest,
}

impl Distributed {
    /// Two back-to-back closes where the operator leaves validator 1 out of
    /// epoch 0 and validator 2 out of epoch 1, so epoch 1 certifies only if
    /// validator 1 fetches epoch 1's predecessor intervals from its
    /// co-holders and seals. `impairment` breaks validator 3's query server,
    /// a co-holder on two of validator 1's three slices.
    fn recovering(impairment: Option<Impairment>) -> Self {
        let mut engine = Self::new(&[], false);
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let first = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            DISTRIBUTED_DEPOSIT,
            2,
            3,
        );
        let second = close_fixture(&protocol, 1, first.successor, DISTRIBUTED_DEPOSIT_1, 5, 6);
        engine.expected_root = second.result.finalized.successor_root;
        engine.undealt = [(0, 1), (1, 2)].into_iter().collect();
        engine.impaired = impairment.map(|impairment| (3, impairment));
        engine.epochs = 2;
        engine.fetcher = Some(1);
        engine
    }

    fn new(silent: &[usize], expect_fault: bool) -> Self {
        let mut rng = test_rng();
        let SchemeFixture {
            mut participants,
            schemes,
            ..
        } = scheme_mocks::fixture(&mut rng, NAMESPACE, 4);
        let operator = ed25519::PrivateKey::from_seed(77_777).public_key();
        participants.push(operator);

        // The settled root and deposit id are deadline-independent, so a
        // throwaway harness-certified fixture pins the expectations.
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let epoch = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            DISTRIBUTED_DEPOSIT,
            2,
            3,
        );
        let finalized = (0..participants.len())
            .map(|_| Finalized::default())
            .collect();
        Self {
            participants,
            schemes,
            finalized,
            driver: ClientResult::default(),
            silent: silent.iter().copied().collect(),
            impaired_accepts: Arc::default(),
            undealt: std::collections::BTreeMap::new(),
            impaired: None,
            epochs: 1,
            fetcher: None,
            expect_fault,
            expected_root: epoch.result.finalized.successor_root,
            deposit_id: epoch.deposit.id,
        }
    }

    /// Index of the operator node in the participant list.
    const fn operator(&self) -> usize {
        self.participants.len() - 1
    }
}

impl EngineDefinition for Distributed {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = State;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (0, TEST_QUOTA), // votes
            (1, TEST_QUOTA), // certificates
            (2, TEST_QUOTA), // resolver
            (3, TEST_QUOTA), // backfill
            (4, TEST_QUOTA), // broadcast
            (5, TEST_QUOTA), // settlement transactions
            (6, TEST_QUOTA), // settlement DA
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            delayed: _,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;

        let validators = self.participants[..self.operator()].to_vec();
        let operator_key = self.participants[self.operator()].clone();
        let partition_prefix = if index == self.operator() {
            "operator".to_string()
        } else {
            format!("validator-{index}")
        };
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let db_config = config(&partition_prefix, &context);

        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let settlement_tx_network = channels.next().unwrap();
        let settlement_da_network = channels.next().unwrap();

        // The operator registers the secondary arrangement at a successor
        // set id (peer sets are append-only): the validators stay primary
        // and the operator is the tracked secondary, so mechanisms favor
        // the committee but gossip to and answer the operator.
        if index == self.operator() {
            let mut manager = oracle.manager();
            let primary =
                commonware_utils::ordered::Set::from_iter_dedup(validators.iter().cloned());
            let secondary = commonware_utils::ordered::Set::from_iter_dedup([public_key.clone()]);
            let _ = commonware_p2p::Manager::track(
                &mut manager,
                1,
                commonware_p2p::TrackedPeers::new(primary.clone(), secondary),
            );
            let peers = commonware_p2p::Provider::peer_set(&mut manager, 1)
                .await
                .expect("the tracked peer set is registered");
            assert_eq!(peers.primary, primary);
            assert!(peers.secondary.iter().any(|peer| peer == public_key));
        }

        // Marshal resolver.
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(100),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill_network,
        );

        // Buffered broadcast engine.
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: NZUsize!(100),
                deque_size: 10,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            },
        );
        broadcast_engine.start(broadcast_network);

        // Prunable archives backing marshal.
        let archive_config = |name: &str| prunable::Config {
            translator: TwoCap,
            key_partition: format!("{partition_prefix}-{name}-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-{name}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(10),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        };
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config("finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks =
            prunable::Archive::init(context.child("finalized_blocks"), archive_config("blocks"))
                .await
                .expect("failed to initialize blocks archive");

        // Genesis block shared by every node, dated at the simulated
        // deployment start.
        let genesis_block = Block::genesis(
            validators[0].clone(),
            chain_id(&deployments()),
            0,
            initial_sync_target::<deterministic::Context>(),
        );

        let startup = context.child("stateful_startup");
        let plan = SyncPlan::init(&startup, partition_prefix.clone()).await;
        let _ = plan.should_state_sync(false);
        let scheme = self.schemes[index.min(self.schemes.len() - 1)].clone();
        let provider = ConstantProvider::new(scheme.clone());

        // Marshal actor.
        let (marshal_actor, marshal_mailbox, floor) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: provider.clone(),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: plan.marshal_start(genesis_block.clone()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(100),
                    view_retention: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;

        // The operator runs the follower stack: no ingress, no consensus
        // engine, the certificate-channel feed in their place.
        if index == self.operator() {
            let finalized = self.finalized[index].clone();
            let application: App<Scheme, ()> = App::new(
                genesis_block.clone(),
                Timing::DEFAULT,
                deployments(),
                finalized.clone(),
            );
            let (stateful_actor, stateful_mailbox) = StatefulActor::init(
                context.child("stateful"),
                StatefulConfig {
                    application,
                    db_config,
                    provider: (),
                    marshal: (marshal_mailbox.clone(), floor),
                    mailbox_size: NZUsize!(100),
                    plan,
                    resolvers: NoopResolver,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(16),
                        apply_batch_size: NZU64!(64),
                        max_outstanding_requests: 8,
                        update_channel_size: NZUsize!(256),
                        max_retained_roots: 8,
                    },
                    prune_config: None,
                },
            );
            let reader_mailbox = stateful_mailbox.clone();
            let reader: StateReader = Arc::new(move |key: StateKey| {
                let mailbox = reader_mailbox.clone();
                Box::pin(async move {
                    let databases = mailbox.subscribe_databases().await;
                    let guard = databases.read().await;
                    guard.get(&key).await.expect("state read must succeed")
                })
            });
            let marshal_reporters =
                MonitorReporter::new(public_key.clone(), monitor, stateful_mailbox.clone());
            marshal_actor.start(marshal_reporters, buffer, resolver);
            stateful_actor.start();
            node::drain(context.child("vote_drain"), vote_network.1);
            node::drain(context.child("resolver_drain"), resolver_network.1);
            node::drain(context.child("tx_drain"), settlement_tx_network.1);
            node::follow(
                context.child("follow"),
                provider,
                marshal_mailbox.clone(),
                certificate_network.1,
            );

            // The local chain backend and the close pipeline.
            let db = stateful_mailbox.subscribe_databases().await;
            let backend = Node::new(deployment(), db, finalized.clone(), settlement_tx_network.0);
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (certifier, pipeline) = node::Certifier::new(
                context.child("certifier"),
                node::Config {
                    verifier: protocol.verifier(),
                    chain: backend.clone(),
                    mailbox_size: NZUsize!(100),
                },
            );
            let handle = certifier.start(settlement_da_network);

            // The driver: the operator's close worker flow as one task.
            let verdict = self.driver.clone();
            let plan = Drive {
                expect_fault: self.expect_fault,
                epochs: self.epochs,
                undealt: self.undealt.clone(),
                fetcher: self.fetcher,
                impaired: self.impaired.map(|(index, _)| index),
            };
            let scheme_for_reads = scheme.clone();
            context.child("driver").spawn(move |context| async move {
                let result = drive(
                    context,
                    backend,
                    pipeline,
                    validators,
                    scheme_for_reads,
                    Engine::query_address(0),
                    plan,
                )
                .await
                .map_err(|error| format!("{error:#}"));
                *verdict.lock() = Some(result);
            });

            return (
                handle,
                State {
                    marshal: marshal_mailbox,
                    reader,
                    finalized,
                    client: self.driver.clone(),
                },
            );
        }

        // Validators run the full consensus stack plus the sealer (unless
        // configured silent, which models a validator that never votes).
        let (ingress_actor, ingress_mailbox) = ingress::Actor::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(100),
                capacity: NZUsize!(1_024),
                bytes: NZUsize!(64 * 1024 * 1024),
                seen: NZUsize!(4_096),
                lease: 5,
            },
        );
        ingress_actor.start(settlement_tx_network);

        let finalized = self.finalized[index].clone();
        let application: App<Scheme, ingress::Mailbox> = App::new(
            genesis_block.clone(),
            Timing::DEFAULT,
            deployments(),
            finalized.clone(),
        );
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                provider: ingress_mailbox.clone(),
                marshal: (marshal_mailbox.clone(), floor),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: NoopResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
                prune_config: None,
            },
        );
        let reader_mailbox = stateful_mailbox.clone();
        let reader: StateReader = Arc::new(move |key: StateKey| {
            let mailbox = reader_mailbox.clone();
            Box::pin(async move {
                let databases = mailbox.subscribe_databases().await;
                let guard = databases.read().await;
                guard.get(&key).await.expect("state read must succeed")
            })
        });

        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let marshal_reporters = MonitorReporter::new(
            public_key.clone(),
            monitor,
            Reporters::from((stateful_mailbox.clone(), ingress_mailbox.clone())),
        );
        marshal_actor.start(marshal_reporters, buffer, resolver);
        stateful_actor.start();

        // The sealing actor on the DA channel, keyed by the validator's
        // dealt clearing committee key.
        let db = stateful_mailbox.subscribe_databases().await;
        let sealer = if self.silent.contains(&index) {
            node::drain(context.child("da_drain"), settlement_da_network.1);
            None
        } else {
            let (sealer, mailbox) = da::Sealer::new(
                context.child("sealer"),
                da::Config {
                    scheme: commonware_clearing::bajillion::admission::bls12381::Scheme::signer(
                        committee().unwrap(),
                        clearing_private(index).unwrap(),
                    )
                    .unwrap(),
                    operators: vec![(operator_key, deployments().remove(0))],
                    db: db.clone(),
                    partition: format!("{partition_prefix}-dealings"),
                    validators: validator_entries(),
                    fetch_timeout: Duration::from_millis(50),
                },
            );
            sealer.start(settlement_da_network);
            Some(mailbox)
        };

        // Certified query server over the applied database, or the impaired
        // stand-in that answers evidence requests wrongly or never.
        match self.impaired {
            Some((impaired, impairment)) if impaired == index => {
                impaired_query(
                    context.child("query"),
                    Engine::query_address(index),
                    impairment,
                    sealer,
                    self.impaired_accepts.clone(),
                );
            }
            _ => {
                query::start(
                    context.child("query"),
                    query::Config {
                        address: Engine::query_address(index),
                        deployments: deployments(),
                        db,
                        finalized: finalized.clone(),
                        marshal: marshal_mailbox.clone(),
                        ingress: ingress_mailbox,
                        sealer,
                    },
                );
            }
        }

        // Simplex engine.
        let engine = simplex::Engine::new(
            context,
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: oracle.control(public_key.clone()),
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox.clone(),
                strategy: Sequential,
                partition: format!("{partition_prefix}-simplex"),
                mailbox_size: NZUsize!(3),
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Genesis(genesis_block.digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_millis(500),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: simplex::SkipBudget::Participants,
                },
                fetch_timeout: Duration::from_secs(2),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );
        let handle = engine.start(vote_network, certificate_network, resolver_network);

        (
            handle,
            State {
                marshal: marshal_mailbox,
                reader,
                finalized,
                client: self.driver.clone(),
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

/// What the distributed driver closes and checks.
struct Drive {
    /// Whether epoch 0's registration is expected to expire into the
    /// deadline fault instead of certifying.
    expect_fault: bool,
    /// Epochs closed back to back.
    epochs: u64,
    /// Per epoch, the validator left out of the operator's deals.
    undealt: std::collections::BTreeMap<u64, usize>,
    /// The validator whose fetched epoch-1 predecessor intervals are compared
    /// against its co-holders' after the run.
    fetcher: Option<usize>,
    /// The validator whose query server is impaired, skipped as a comparison
    /// co-holder.
    impaired: Option<usize>,
}

/// One slice's retained interval at `root` as validator `address` serves it.
async fn interval(
    context: &deterministic::Context,
    address: std::net::SocketAddr,
    root: VectorRoot<Digest>,
    slice: u16,
) -> anyhow::Result<da::SliceRange> {
    let request = EvidenceRequest::new(deployment(), EvidenceLookup::Interval { root, slice });
    let body = rpc::invoke(
        context,
        address,
        "validator",
        query::METHOD_EVIDENCE,
        request.encode(),
    )
    .await?;
    match EvidenceResponse::decode(body)? {
        EvidenceResponse::Served(Evidence::Interval(range)) => Ok(range),
        other => anyhow::bail!("validator at {address} answered {other:?} for slice {slice}"),
    }
}

/// The operator's distributed close worker flow, driven end to end against
/// its own followed state for each planned epoch: deposit, boundary-only
/// registration and the certified read-back of its assigned deadlines,
/// dealing dissemination and vote collection through the pipeline, certified
/// admission, and finally the agent-visible certified reads over a
/// validator's query server. When a validator was planned to miss epoch 0,
/// its fetched epoch-1 predecessor intervals are then compared byte for byte
/// against every healthy co-holder's.
async fn drive(
    mut context: deterministic::Context,
    mut chain: Node<deterministic::Context, TxSender>,
    pipeline: node::Mailbox,
    validators: Vec<ed25519::PublicKey>,
    scheme: Scheme,
    query: std::net::SocketAddr,
    plan: Drive,
) -> anyhow::Result<()> {
    let protocol = Protocol::new(NonZeroUsize::MIN)?;
    let state = genesis_cache();
    let mut latest = light::Latest::default();
    let mut predecessor = state.leaves().to_vec();
    let mut settled = Vec::new();
    for epoch in 0..plan.epochs {
        let label = deposit_label(epoch);

        // The deposit carries no deadline, so it lands first: the
        // boundary-only registration commits its root. The local backend
        // serves nothing until the follower applied a finalized block, and
        // each submission completes on the local certified read of its
        // effect record.
        let (deposit, deposit_tx, register_tx) =
            fixture_boundary(&protocol, epoch, &predecessor, label);
        chain.deliver(&context, &deposit_tx).await?;
        let mut deposited = false;
        for _ in 0..600 {
            if chain.deposit(&context, deposit.id).await.ok().flatten() == Some(deposit.clone()) {
                deposited = true;
                break;
            }
            context.sleep(Duration::from_millis(200)).await;
        }
        anyhow::ensure!(
            deposited,
            "the epoch {epoch} deposit earned no custody record"
        );
        chain.deliver(&context, &register_tx).await?;

        // Execution assigned the deadlines at the registration's inclusion
        // height, so the close is built only after the local certified
        // registration read reveals them: the operator's read-back flow.
        let mut registered = None;
        for _ in 0..600 {
            if let Ok(Some(record)) = chain.registration(&context).await
                && record.epoch == epoch
            {
                registered = Some(record);
                break;
            }
            context.sleep(Duration::from_millis(200)).await;
        }
        let Some(record) = registered else {
            anyhow::bail!("the registered epoch {epoch} left no certified record");
        };
        let build = build_fixture(
            &protocol,
            epoch,
            predecessor.clone(),
            label,
            record.admission_deadline,
            record.challenge_deadline,
        );
        anyhow::ensure!(
            build.deposit_tx == deposit_tx && build.register_tx == register_tx,
            "the fixture boundary diverged from the submitted transactions"
        );
        let admission_deadline = record.admission_deadline;

        // The close worker flow: deal the slices once, assemble
        // per-validator dealings, certify over the DA channel. A validator
        // planned to miss this close is dealt nothing.
        let slices = protocol.slices(&build.prepared)?;
        let dealings = protocol.dealings(&build.prepared, &slices)?;
        let dealing_slices = dealings.iter().map(Vec::len).sum();
        let header = build.prepared.close().header;
        let roots = build.prepared.close().roots;
        let mut deals = Vec::new();
        for (index, peer) in validators.iter().enumerate() {
            if plan.undealt.get(&epoch) == Some(&index) {
                continue;
            }
            let participant = dealt_participant(index)?;
            deals.push(node::Deal::new(
                participant,
                peer.clone(),
                epoch,
                header,
                roots,
                dealings[usize::from(participant)].clone(),
            ));
        }

        if plan.expect_fault {
            // Quorum is unreachable: the certificate must never assemble,
            // and the registration expires into the deadline fault at its
            // exact absolute height.
            let certified: Arc<Mutex<Option<()>>> = Arc::default();
            {
                let certified = certified.clone();
                context.child("certify").spawn(move |_| async move {
                    if pipeline.certify(0, header, deals).await.is_ok() {
                        *certified.lock() = Some(());
                    }
                });
            }
            for _ in 0..600 {
                if let Some(FaultRecord::Faulted(reason)) = chain.fault(&context).await? {
                    match reason {
                        HardFaultReasonResponse::ExpiredRegistration {
                            epoch: 0,
                            expired_at,
                            ..
                        } => {
                            anyhow::ensure!(
                                expired_at == admission_deadline,
                                "the registration expired at {expired_at}, not its deadline"
                            );
                            anyhow::ensure!(
                                certified.lock().is_none(),
                                "two silent validators still assembled a certificate"
                            );
                            return Ok(());
                        }
                        reason => anyhow::bail!("unexpected fault: {reason:?}"),
                    }
                }
                context.sleep(Duration::from_millis(200)).await;
            }
            anyhow::bail!("the registration never expired into the deadline fault")
        }

        // Certification, local completion, and certified admission.
        let certificate = pipeline.certify(epoch, header, deals).await?;
        let result = protocol.certify(
            build.prepared,
            slices.len(),
            dealing_slices,
            certificate,
            0,
            0,
        )?;
        pipeline
            .admit(
                crate::chain::tx::AdmitRequest::from(&result),
                result.finalized,
                result.roots.change,
            )
            .await?;

        // The agents' certified reads see the distributed close: verified
        // light client reads against a validator's query server.
        loop {
            let (verified, _) =
                verified_read(&mut context, &scheme, query, &req(Lookup::Status)).await?;
            latest
                .observe(verified.height)
                .map_err(|error| anyhow::anyhow!("status read regressed: {error}"))?;
            let Some(Record::Status(status)) = verified.record else {
                anyhow::bail!("status read returned no record");
            };
            anyhow::ensure!(!status.hard_faulted, "the deployment hard-faulted");
            if status.last_finalized == Some(epoch) {
                anyhow::ensure!(
                    status.state_root == result.finalized.successor_root,
                    "finalized state root diverged from the distributed close"
                );
                break;
            }
            context.sleep(Duration::from_millis(200)).await;
        }
        settled.push(result.finalized.successor_root);
        predecessor = build.successor;
    }
    let deposit_request = req(Lookup::Deposit {
        id: Sha256::hash(&[DISTRIBUTED_DEPOSIT]),
    });
    let (verified, _) = verified_read(&mut context, &scheme, query, &deposit_request).await?;
    anyhow::ensure!(
        matches!(verified.record, Some(Record::Deposit(_))),
        "deposit record was not certified"
    );

    // The validator that missed epoch 0 retains epoch 1's predecessor
    // interval of every slice in its spans exactly as its healthy
    // co-holders do, verifiable at the root epoch 0 settled.
    let Some(fetcher) = plan.fetcher else {
        return Ok(());
    };
    let root = *settled
        .first()
        .context("the fetcher scenario closes epoch 0")?;
    let committee = committee()?;
    let assignment = Assignment::new(committee.commitment::<Sha256>(), SLICE_BITS)?;
    let spans =
        assigned_slice_spans::<Sha256, _>(&committee, &assignment, dealt_participant(fetcher)?)?;
    for slice in spans.iter().flat_map(|span| span.clone()) {
        let fetched = interval(&context, Engine::query_address(fetcher), root, slice).await?;
        fetched.verify(&root, slice, SLICE_BITS)?;
        let mut compared = 0;
        for holder in slice_holders::<Sha256, _>(&committee, &assignment, slice)? {
            let index = (0..validators.len())
                .find(|index| dealt_participant(*index).ok() == Some(holder))
                .context("every holder is a validator")?;
            if index == fetcher || plan.impaired == Some(index) {
                continue;
            }
            let held = interval(&context, Engine::query_address(index), root, slice).await?;
            anyhow::ensure!(
                held.encode() == fetched.encode(),
                "the fetched interval of slice {slice} differs from validator {index}'s"
            );
            compared += 1;
        }
        anyhow::ensure!(
            compared > 0,
            "slice {slice} has no healthy co-holder to compare against"
        );
    }
    Ok(())
}

/// Every node observed the deadline fault: the registration expired with no
/// quorum to certify its close.
#[derive(Clone)]
struct Faulted;

impl Property<ed25519::PublicKey, State> for Faulted {
    fn name(&self) -> &str {
        "registration expired into the deadline fault"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                match (state.reader)(fault_key(&deployment())).await {
                    Some(Record::Fault(FaultRecord::Faulted(
                        HardFaultReasonResponse::ExpiredRegistration { epoch: 0, .. },
                    ))) => {}
                    record => return Err(format!("expected the expiry fault, found {record:?}")),
                }
                let status = match (state.reader)(status_key(&deployment())).await {
                    Some(Record::Status(status)) => status,
                    record => return Err(format!("expected a status record, found {record:?}")),
                };
                if !status.hard_faulted {
                    return Err("the deployment did not hard-fault".into());
                }
            }
            Ok(())
        })
    }
}

#[test]
fn distributed_certification_finalizes_epoch() {
    let engine = Distributed::new(&[], false);
    let expected_root = engine.expected_root;
    let deposit_id = engine.deposit_id;
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(ClientDoneAt { height: 35 })
        .property(Settled {
            expected_root,
            deposit_id,
        })
        .property(Monotonic)
        .property(ClientSucceeded)
        .run()
        .unwrap();
}

#[test]
fn one_silent_validator_still_certifies() {
    // n = 4 with quorum 3: one validator that never votes leaves the exact
    // quorum reachable and the close still certifies and finalizes.
    let engine = Distributed::new(&[1], false);
    let expected_root = engine.expected_root;
    let deposit_id = engine.deposit_id;
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(ClientDoneAt { height: 35 })
        .property(Settled {
            expected_root,
            deposit_id,
        })
        .property(ClientSucceeded)
        .run()
        .unwrap();
}

#[test]
fn two_silent_validators_expire_the_registration() {
    // With two silent validators the exact quorum is unreachable, no
    // certificate assembles, and the registration expires into the deadline
    // fault at its absolute height.
    let engine = Distributed::new(&[1, 2], true);
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(ClientDoneAt { height: 35 })
        .property(Faulted)
        .property(ClientSucceeded)
        .run()
        .unwrap();
}

/// Every validator settled epoch 1 behind the validator that missed epoch
/// 0: two closes finalized, the second sealed over intervals that validator
/// fetched from its co-holders.
#[derive(Clone)]
struct Recovered {
    expected_root: commonware_clearing::bajillion::commitment::VectorRoot<Digest>,
}

impl Property<ed25519::PublicKey, State> for Recovered {
    fn name(&self) -> &str {
        "settlement finalized epoch one after the interval fetch"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let status = match (state.reader)(status_key(&deployment())).await {
                    Some(Record::Status(status)) => status,
                    record => return Err(format!("expected a status record, found {record:?}")),
                };
                if status.last_finalized != Some(1) {
                    return Err(format!(
                        "epoch one did not finalize: {:?}",
                        status.last_finalized
                    ));
                }
                if status.state_root != self.expected_root {
                    return Err("finalized state root diverged from the second close".into());
                }
                if status.custody != 402 || status.claimable != 0 || status.hard_faulted {
                    return Err(format!(
                        "unexpected settled balances: custody {} claimable {} faulted {}",
                        status.custody, status.claimable, status.hard_faulted
                    ));
                }
            }
            Ok(())
        })
    }
}

/// Runs the two-epoch recovery scenario: validator 1 misses epoch 0, fetches
/// every slice in its spans from its co-holders over their query servers
/// when epoch 1 is dealt, seals, and casts the third vote of the exact
/// quorum (validator 2 is left out of epoch 1, and the silent-validator
/// tests above show quorum has no slack). The driver then checks the fetched
/// records against the healthy co-holders' byte for byte.
fn recover(impairment: Option<Impairment>) {
    let engine = Distributed::recovering(impairment);
    let expected_root = engine.expected_root;
    let impaired_accepts = engine.impaired_accepts.clone();
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(ClientDoneAt { height: 45 })
        .property(ClientSucceeded)
        .property(Recovered { expected_root })
        .run()
        .unwrap();

    // An impaired holder was actually asked: the rotation past it is what
    // the variant exercises, not a fetch that happened to skip it.
    assert_eq!(
        impaired_accepts.load(Ordering::Relaxed) > 0,
        impairment.is_some()
    );
}

#[test]
fn missed_close_validator_fetches_intervals_and_seals() {
    recover(None);
}

#[test]
fn interval_fetch_rotates_past_a_garbage_holder() {
    // Validator 3 answers every evidence request with undecodable bytes: the
    // fetch declines it and the other co-holder serves each shared slice.
    recover(Some(Impairment::Garbage));
}

#[test]
fn interval_fetch_rotates_past_a_silent_holder() {
    // Validator 3 accepts every connection and never answers: each attempt
    // on it times out on the runtime clock before the other co-holder is
    // asked.
    recover(Some(Impairment::Silent));
}

#[test]
fn deposit_rejects_values_outside_the_operator_storage_domain() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("domain"), "domain").await;

        // The example operator persists monetary values in SQLite INTEGER
        // columns, so custody beyond that domain is refused before it moves.
        let oversized = deposit_tx(DepositEvent {
            id: Sha256::hash(&[b"domain-deposit"]),
            account: identities()[0].key.clone(),
            amount: crate::protocol::SQLITE_U64_MAX,
        });
        seal(&db, 1, std::slice::from_ref(&oversized)).await;
        assert_eq!(
            read(
                &db,
                &deposit_key(&deployment(), &Sha256::hash(&[b"domain-deposit"]))
            )
            .await,
            None
        );
        assert_eq!(status(&db).await.custody, 400);

        // The rejection is effect-free, so the typed reason surfaces only
        // through the advisory dry-run.
        assert_eq!(
            advise(&db, &deployments(), &oversized).await.unwrap(),
            Advice::Doomed(Reject::Domain)
        );
    });
}

#[test]
fn registration_replays_and_fences_deposits() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("fence"), "fence").await;
        let register = empty_register_tx();
        seal(&db, 1, std::slice::from_ref(&register)).await;
        let record = registration(&db).await;
        assert_eq!(record.epoch, 0);

        // The exact registration replays onto the registration record guard
        // without consuming anything: the record is untouched, deadlines
        // included.
        seal(&db, 2, std::slice::from_ref(&register)).await;
        assert_eq!(registration(&db).await, record);

        // A deposit while the epoch is registered is fenced with no effect:
        // no custody record, no custody moved. The bytes stay retryable.
        let late_event = DepositEvent {
            id: Sha256::hash(&[b"fenced-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        let late = deposit_tx(late_event.clone());
        seal(&db, 3, std::slice::from_ref(&late)).await;
        assert_eq!(
            read(&db, &deposit_key(&deployment(), &late_event.id)).await,
            None
        );
        assert_eq!(status(&db).await.custody, 400);
    });
}

#[test]
fn registration_requires_every_queued_withdrawal_and_openings() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("carriage"), "carriage").await;
        let protocol = Protocol::new(std::num::NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();

        // One withdrawal queues directly on the chain.
        let queued = SignedWithdrawal::sign(
            deployment(),
            state.root().digest,
            Bytes::from_static(b"queued-destination"),
            commonware_clearing::bajillion::boundary::WithdrawalAction::Amount(
                std::num::NonZeroU64::new(7).unwrap(),
            ),
            60,
            wallet.signer(),
        );
        let queue_tx = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: queued.clone(),
            openings: vec![state.opening(&account).unwrap()],
        });
        seal(&db, 1, std::slice::from_ref(&queue_tx)).await;
        assert_eq!(
            read(&db, &withdrawal_key(&deployment(), &account)).await,
            Some(Record::Withdrawal(queued.clone()))
        );

        // A registration omitting the queued request is rejected without
        // consuming the slot.
        let root = commonware_clearing::bajillion::boundary::DepositBatch::<Key>::empty()
            .root::<Sha256>()
            .unwrap();
        let empty = WithdrawalBatch::empty();
        let omitting = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root: root,
            staged_root: root,
            withdrawals: empty.clone(),
            openings: Vec::new(),
            signature: protocol.sign_chain_registration(0, 400, &root, &root, &empty),
        });
        seal(&db, 2, std::slice::from_ref(&omitting)).await;
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
        assert_eq!(read(&db, &anchor_key(&deployment(), 0)).await, None);

        // A queued request needs no opening at registration (the chain proved
        // it at queue time), but an unqueued carried extra does: carrying one
        // without its predecessor-root opening is rejected.
        let extra_wallet = wallets().remove(1);
        let extra = SignedWithdrawal::sign(
            deployment(),
            state.root().digest,
            Bytes::from_static(b"extra-destination"),
            commonware_clearing::bajillion::boundary::WithdrawalAction::Amount(
                std::num::NonZeroU64::new(3).unwrap(),
            ),
            60,
            extra_wallet.signer(),
        );
        let withdrawals = WithdrawalBatch::new(vec![queued.clone(), extra.clone()]).unwrap();
        let unopened = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root: root,
            staged_root: root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature: protocol.sign_chain_registration(0, 400, &root, &root, &withdrawals),
        });
        seal(&db, 3, std::slice::from_ref(&unopened)).await;
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);

        // With the extra's opening supplied, the carriage registers.
        let opened = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root: root,
            staged_root: root,
            withdrawals: withdrawals.clone(),
            openings: vec![state.opening(&extra_wallet.public_key()).unwrap()],
            signature: protocol.sign_chain_registration(0, 400, &root, &root, &withdrawals),
        });
        seal(&db, 4, std::slice::from_ref(&opened)).await;
        assert!(matches!(
            read(&db, &registration_key(&deployment())).await,
            Some(Record::Registration(_))
        ));
    });
}

#[test]
fn successor_window_opens_at_admission() {
    deterministic::Runner::default().start(|context| async move {
        let protocol = Protocol::new(std::num::NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let db = open(context.child("window"), "window").await;

        // Epoch 0 registers at height 1: the chain assigns its admission
        // deadline at height 11 and its challenge deadline at height 12.
        let first = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"chain-window-0",
            11,
            12,
        );
        seal(
            &db,
            1,
            &[first.deposit_tx.clone(), first.register_tx.clone()],
        )
        .await;

        // The successor's window has not opened yet: epoch 0 is registered
        // but not admitted, so a successor registration is rejected on the
        // epoch sequence with no effect: the live epoch-0 registration is
        // untouched.
        let second = close_fixture(
            &protocol,
            1,
            first.successor.clone(),
            b"chain-window-1",
            14,
            15,
        );
        seal(&db, 2, std::slice::from_ref(&second.register_tx)).await;
        let live = registration(&db).await;
        assert_eq!(live.epoch, 0);
        assert_eq!(live.admitted, None);
        assert_eq!(read(&db, &anchor_key(&deployment(), 1)).await, None);

        // Epoch 0's admission at height 3 immediately opens the successor's
        // window: the exact same registration bytes land in the next block,
        // while epoch 0's challenge window (through height 12) is still open,
        // and the successor's deadlines anchor at ITS inclusion height
        // (heights 14 and 15).
        seal(&db, 3, std::slice::from_ref(&first.admit_tx)).await;
        seal(
            &db,
            4,
            &[second.deposit_tx.clone(), second.register_tx.clone()],
        )
        .await;
        let registered = registration(&db).await;
        assert_eq!(registered.epoch, 1);
        assert_eq!(registered.admission_deadline, 14);
        assert_eq!(registered.challenge_deadline, 15);
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted)) if !admitted.finalized
        ));

        // Epoch 1 admits behind epoch 0 while both challenge windows run.
        seal(&db, 5, std::slice::from_ref(&second.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 1)).await,
            Some(Record::Admitted(admitted)) if !admitted.finalized
        ));

        // Both finalize in order at their own real heights, and epoch 0's
        // finalization leaves the successor's live registration record in
        // place.
        for height in 6..=12 {
            seal(&db, height, &[]).await;
        }
        assert_eq!(status(&db).await.last_finalized, None);
        seal(&db, 13, &[]).await;
        assert_eq!(status(&db).await.last_finalized, Some(0));
        assert!(matches!(
            read(&db, &registration_key(&deployment())).await,
            Some(Record::Registration(record)) if record.epoch == 1
        ));
        for height in 14..=16 {
            seal(&db, height, &[]).await;
        }
        let settled = status(&db).await;
        assert_eq!(settled.last_finalized, Some(1));
        assert_eq!(settled.state_root, second.result.finalized.successor_root);
        assert_eq!(settled.custody, 402);
        assert!(!settled.hard_faulted);
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
    });
}

#[test]
fn live_obligations_keep_registration_available() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("live"), "live").await;

        // A recorded deposit and a queued withdrawal start liveness clocks,
        // but neither prevents idle blocks from passing nor the later
        // registration from landing.
        let deposit_event = DepositEvent {
            id: Sha256::hash(&[b"live-obligation-deposit"]),
            account: identities()[0].key.clone(),
            amount: 1,
        };
        let deposit = deposit_tx(deposit_event.clone());
        let state = genesis_cache();
        let wallet = wallets().remove(1);
        let withdrawal = SignedWithdrawal::sign(
            deployment(),
            state.root().digest,
            Bytes::from_static(b"live-destination"),
            commonware_clearing::bajillion::boundary::WithdrawalAction::Amount(
                std::num::NonZeroU64::new(7).unwrap(),
            ),
            60,
            wallet.signer(),
        );
        let queue_tx = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: withdrawal.clone(),
            openings: vec![state.opening(&wallet.public_key()).unwrap()],
        });
        seal(&db, 1, &[deposit.clone(), queue_tx.clone()]).await;
        assert!(matches!(
            read(&db, &deposit_key(&deployment(), &deposit_event.id)).await,
            Some(Record::Deposit(_))
        ));
        assert!(matches!(
            read(&db, &withdrawal_key(&deployment(), &wallet.public_key())).await,
            Some(Record::Withdrawal(_))
        ));
        for height in 2..=5 {
            seal(&db, height, &[]).await;
        }
        assert!(!status(&db).await.hard_faulted);

        // The registration must carry the queued withdrawal verbatim, and the
        // boundary must match the recorded custody.
        let protocol = Protocol::new(std::num::NonZeroUsize::MIN).unwrap();
        let deposits = commonware_clearing::bajillion::boundary::DepositBatch::new(vec![
            commonware_clearing::bajillion::boundary::DepositRecord::new(
                identities()[0].key.clone(),
                1,
            )
            .unwrap(),
        ])
        .unwrap();
        let deposits_root = deposits.root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::new(vec![withdrawal]).unwrap();
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,
            staged_root: deposits_root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature: protocol.sign_chain_registration(
                0,
                400,
                &deposits_root,
                &deposits_root,
                &withdrawals,
            ),
        });
        seal(&db, 6, std::slice::from_ref(&register)).await;
        assert_eq!(registration(&db).await.epoch, 0);
        assert!(!status(&db).await.hard_faulted);
    });
}

#[test]
fn out_of_order_registration_is_rejected_without_consuming_the_slot() {
    deterministic::Runner::default().start(|context| async move {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let db = open(context.child("order"), "order").await;

        // A valid-shaped registration for epoch 2 while epoch 0 is expected:
        // an empty boundary over the liability the chain will hold once
        // epochs 0 and 1 settle their unit deposits.
        let root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let premature = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 2,
            predecessor_liability: 402,
            deposits_root: root,
            staged_root: root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature: protocol.sign_chain_registration(2, 402, &root, &root, &withdrawals),
        });

        // The premature registration is rejected on the epoch sequence and
        // consumes nothing: no registration record, no anchor.
        seal(&db, 1, std::slice::from_ref(&premature)).await;
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
        assert_eq!(read(&db, &anchor_key(&deployment(), 2)).await, None);

        // Epoch 0 registers normally and admits, then epoch 1 follows, so
        // epoch 2 becomes the next admissible extension of the pipeline.
        let first = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"chain-order-0",
            12,
            13,
        );
        seal(
            &db,
            2,
            &[first.deposit_tx.clone(), first.register_tx.clone()],
        )
        .await;
        assert_eq!(registration(&db).await.epoch, 0);
        seal(&db, 3, std::slice::from_ref(&first.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(_))
        ));
        let second = close_fixture(
            &protocol,
            1,
            first.successor.clone(),
            b"chain-order-1",
            14,
            15,
        );
        seal(
            &db,
            4,
            &[second.deposit_tx.clone(), second.register_tx.clone()],
        )
        .await;
        assert_eq!(registration(&db).await.epoch, 1);
        seal(&db, 5, std::slice::from_ref(&second.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 1)).await,
            Some(Record::Admitted(_))
        ));

        // A rejection writes nothing, so the premature submission recovers
        // by resubmitting the original bytes with no re-signing: the same
        // transaction lands once its epoch becomes the next admissible
        // extension, purely through the domain guards. The deadlines are
        // assigned at this inclusion height (6 plus the default offset),
        // not the first one.
        seal(&db, 6, std::slice::from_ref(&premature)).await;
        let record = registration(&db).await;
        assert_eq!(record.epoch, 2);
        assert_eq!(record.admission_deadline, 16);
        assert_eq!(record.challenge_deadline, 17);
        assert!(matches!(
            read(&db, &anchor_key(&deployment(), 2)).await,
            Some(Record::Anchor(_))
        ));
    });
}

#[test]
fn invalid_registration_arms_reject_and_recover() {
    deterministic::Runner::default().start(|context| async move {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let state = genesis_cache();
        let db = open(context.child("recover"), "recover").await;

        // The epoch-0 fixture the walk recovers to: registered at height 3,
        // so its assigned deadlines are heights 13 and 14.
        let epoch = close_fixture(
            &protocol,
            0,
            state.leaves().to_vec(),
            b"chain-recover-0",
            13,
            14,
        );

        // The registration with one signature byte flipped fails
        // authentication and consumes nothing.
        let mut corrupted = match epoch.register_tx.clone() {
            SettlementTx::RegisterEpoch(register) => register,
            _ => unreachable!(),
        };
        let mut raw = corrupted.signature.encode().to_vec();
        raw[0] ^= 1;
        corrupted.signature = Signature::decode(raw.as_slice()).unwrap();
        let corrupted = SettlementTx::RegisterEpoch(corrupted);
        seal(&db, 1, std::slice::from_ref(&corrupted)).await;
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
        assert_eq!(
            advise(&db, &deployments(), &corrupted).await.unwrap(),
            Advice::Doomed(Reject::Signature)
        );

        // A registration whose signed deposit boundary carries a unit deposit
        // the chain never recorded diverges from settlement custody once the
        // staged view has matched, and consumes nothing.
        let empty_root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
        let divergent_root = DepositBatch::new(vec![
            DepositRecord::new(identities()[0].key.clone(), 1).unwrap(),
        ])
        .unwrap()
        .root::<Sha256>()
        .unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let divergent = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root: divergent_root,
            staged_root: empty_root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature: protocol.sign_chain_registration(
                0,
                400,
                &divergent_root,
                &empty_root,
                &withdrawals,
            ),
        });
        seal(&db, 2, std::slice::from_ref(&divergent)).await;
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);

        // The correct registration lands on the untouched slot, admits, and
        // finalizes at its real heights.
        seal(
            &db,
            3,
            &[epoch.deposit_tx.clone(), epoch.register_tx.clone()],
        )
        .await;
        assert_eq!(registration(&db).await.epoch, 0);
        seal(&db, 4, std::slice::from_ref(&epoch.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(_))
        ));
        for height in 5..=14 {
            seal(&db, height, &[]).await;
        }
        assert_eq!(status(&db).await.last_finalized, None);
        seal(&db, 15, &[]).await;
        let finalized = status(&db).await;
        assert_eq!(finalized.last_finalized, Some(0));
        assert_eq!(finalized.custody, 401);
        assert!(!finalized.hard_faulted);
        assert_eq!(read(&db, &registration_key(&deployment())).await, None);
    });
}

#[test]
fn conflicting_registration_is_rejected_while_active() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("conflict"), "conflict").await;
        seal(
            &db,
            1,
            &[fixture.deposit_tx.clone(), fixture.register_tx.clone()],
        )
        .await;
        let original = registration(&db).await;
        assert_eq!(original.epoch, 0);
        assert_eq!(original.admitted, None);

        // A second, different valid-shaped registration for the registered
        // epoch: an empty boundary instead of the fixture's unit deposit.
        // The live registration record trips the state-level conflict guard,
        // with no effect, and the advisory dry-run names the conflict.
        let conflicting = empty_register_tx();
        assert_eq!(
            advise(&db, &deployments(), &conflicting).await.unwrap(),
            Advice::Doomed(Reject::RegistrationConflict)
        );
        seal(&db, 2, std::slice::from_ref(&conflicting)).await;

        // The original registration is untouched and proceeds to admission.
        assert_eq!(
            read(&db, &registration_key(&deployment())).await,
            Some(Record::Registration(original.clone()))
        );
        seal(&db, 3, std::slice::from_ref(&fixture.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted)) if !admitted.finalized
        ));
        assert!(matches!(
            read(&db, &registration_key(&deployment())).await,
            Some(Record::Registration(record)) if record.admitted.is_some()
        ));
    });
}

#[test]
fn admit_requires_a_valid_committee_certificate() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("certificate"), "certificate").await;
        seal(
            &db,
            1,
            &[fixture.deposit_tx.clone(), fixture.register_tx.clone()],
        )
        .await;
        let live = registration(&db).await;
        assert_eq!(live.admitted, None);
        let genuine = match &fixture.admit_tx {
            SettlementTx::Admit(request) => request.clone(),
            _ => unreachable!(),
        };

        // A garbage admission consumes nothing: after every forged variant
        // below, the registration record survives byte-identical, no close
        // is admitted, and custody is untouched.
        let unconsumed = |db: &Database<deterministic::Context>, live: &Record| {
            let db = db.clone();
            let live = live.clone();
            async move {
                assert_eq!(read(&db, &admitted_key(&deployment(), 0)).await, None);
                assert_eq!(
                    read(&db, &registration_key(&deployment())).await,
                    Some(live)
                );
                assert_eq!(status(&db).await.custody, 401);
            }
        };
        let live = Record::Registration(live);

        // Tampered aggregate signature bytes: the aggregate is the
        // encoding's trailing bytes and its point decodes lazily, so the
        // transaction still decodes and only certificate verification at
        // execution rejects it.
        let mut tampered = fixture.admit_tx.encode().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = SettlementTx::decode(Bytes::from(tampered)).unwrap();
        assert_ne!(tampered, fixture.admit_tx);
        seal(&db, 2, std::slice::from_ref(&tampered)).await;
        unconsumed(&db, &live).await;

        // A signer swapped inside the bitmap: the count still reads exactly
        // quorum, but the aggregate no longer matches the named signers.
        let signed = genuine.certificate.signers.iter().collect::<Vec<_>>();
        let absent = (0..4)
            .map(Participant::from_usize)
            .find(|candidate| !signed.contains(candidate))
            .expect("a 3-of-4 certificate leaves one validator unsigned");
        let mut swapped = genuine.clone();
        swapped.certificate.signers = Signers::new(
            4,
            std::iter::once(absent).chain(signed[1..].iter().copied()),
        )
        .unwrap();
        let swapped = SettlementTx::Admit(swapped);
        seal(&db, 3, std::slice::from_ref(&swapped)).await;
        unconsumed(&db, &live).await;

        // Fewer than quorum: assemble_exact cannot even construct one (see
        // the certificate unit tests), so forge the encoding directly, which
        // the codec permits. Exact-cardinality verification rejects it.
        let mut subquorum = genuine.clone();
        subquorum.certificate.signers = Signers::new(4, signed[..2].iter().copied()).unwrap();
        let subquorum = SettlementTx::Admit(subquorum);
        assert_eq!(SettlementTx::decode(subquorum.encode()).unwrap(), subquorum);
        seal(&db, 4, std::slice::from_ref(&subquorum)).await;
        unconsumed(&db, &live).await;

        // A bitmap that is not the committee's exact length is refused at
        // the transaction codec, before execution ever sees it.
        let mut short = genuine.clone();
        short.certificate.signers = Signers::new(3, [signed[0]]).unwrap();
        assert!(matches!(
            SettlementTx::decode(SettlementTx::Admit(short).encode()),
            Err(CodecError::Invalid(_, _))
        ));

        // The untouched registration still accepts the genuine certificate.
        seal(&db, 5, std::slice::from_ref(&fixture.admit_tx)).await;
        assert!(matches!(
            read(&db, &admitted_key(&deployment(), 0)).await,
            Some(Record::Admitted(admitted))
                if admitted.batch_id == fixture.result.finalized.batch_id
        ));
        assert!(matches!(
            read(&db, &registration_key(&deployment())).await,
            Some(Record::Registration(record)) if record.admitted.is_some()
        ));
    });
}

#[test]
fn admit_from_any_submitter_lands() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();

        // The transaction carries no submitter identity: its wire bytes are
        // exactly the certified close material, so a third-party relay
        // reconstructs the identical transaction from gossip alone.
        let relayed = SettlementTx::decode(fixture.admit_tx.encode()).unwrap();
        assert_eq!(relayed, fixture.admit_tx);

        // Land the operator-built transaction on one chain and the relayed
        // bytes on another: execution has no source concept, so both chains
        // admit the same close and commit identical roots.
        let operator_db = open(context.child("submitter_a"), "submitter-a").await;
        let relay_db = open(context.child("submitter_b"), "submitter-b").await;
        let setup = [fixture.deposit_tx.clone(), fixture.register_tx.clone()];
        assert_eq!(
            seal(&operator_db, 1, &setup).await,
            seal(&relay_db, 1, &setup).await
        );
        assert_eq!(
            seal(&operator_db, 2, std::slice::from_ref(&fixture.admit_tx)).await,
            seal(&relay_db, 2, std::slice::from_ref(&relayed)).await
        );
        for db in [&operator_db, &relay_db] {
            assert!(matches!(
                read(db, &admitted_key(&deployment(), 0)).await,
                Some(Record::Admitted(admitted))
                    if admitted.batch_id == fixture.result.finalized.batch_id
            ));
        }
    });
}

#[test]
fn begin_hard_fault_is_not_a_griefing_lever() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("no_grief"), "no-grief").await;
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: deployment(),
        });

        // Live obligations, none expired: the permissionless begin is
        // rejected with no effect, because the fault it observes is entered
        // only by block production observing a real expired deadline (the
        // expired_registration/deposit/withdrawal trio pins those arms) or a
        // proven challenge (proven_challenge_inside_the_window pins that
        // one), never by this transaction.
        seal(
            &db,
            1,
            &[
                fixture.deposit_tx.clone(),
                fixture.register_tx.clone(),
                begin.clone(),
            ],
        )
        .await;
        assert!(!status(&db).await.hard_faulted);
        assert_eq!(read(&db, &fault_key(&deployment())).await, None);
        assert_eq!(registration(&db).await.admitted, None);
        assert_eq!(
            advise(&db, &deployments(), &begin).await.unwrap(),
            Advice::Doomed(Reject::FaultUnavailable)
        );

        // Against the admitted close it stays inert, and the pipeline
        // finalizes cleanly at its real heights.
        seal(&db, 2, std::slice::from_ref(&fixture.admit_tx)).await;
        seal(&db, 3, std::slice::from_ref(&begin)).await;
        assert!(!status(&db).await.hard_faulted);
        assert_eq!(read(&db, &fault_key(&deployment())).await, None);
        for height in 4..=12 {
            seal(&db, height, &[]).await;
        }
        seal(&db, 13, &[]).await;
        let finalized = status(&db).await;
        assert_eq!(finalized.last_finalized, Some(0));
        assert!(!finalized.hard_faulted);
    });
}

#[test]
fn advisory_dry_run_classifies_submissions() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = epoch_fixture();
        let db = open(context.child("advice"), "advice").await;

        // A fresh chain: intake is plausible, hard-fault transitions are
        // doomed, and a stranger's deposit is doomed statelessly.
        assert_eq!(
            advise(&db, &deployments(), &fixture.deposit_tx)
                .await
                .unwrap(),
            Advice::Plausible
        );
        assert_eq!(
            advise(&db, &deployments(), &fixture.register_tx)
                .await
                .unwrap(),
            Advice::Plausible
        );
        let stranger = deposit_tx(DepositEvent {
            id: Sha256::hash(&[b"advice-stranger"]),
            account: crate::protocol::Wallet::from_seed("stranger", 999).public_key(),
            amount: 1,
        });
        assert_eq!(
            advise(&db, &deployments(), &stranger).await.unwrap(),
            Advice::Doomed(Reject::UnknownAccount)
        );
        assert_eq!(
            advise(&db, &deployments(), &fixture.admit_tx)
                .await
                .unwrap(),
            Advice::Doomed(Reject::NotRegistered)
        );

        // Landed effects answer Applied, and conflicting reuse is doomed.
        seal(
            &db,
            1,
            &[fixture.deposit_tx.clone(), fixture.register_tx.clone()],
        )
        .await;
        assert_eq!(
            advise(&db, &deployments(), &fixture.deposit_tx)
                .await
                .unwrap(),
            Advice::Applied
        );
        assert_eq!(
            advise(&db, &deployments(), &fixture.register_tx)
                .await
                .unwrap(),
            Advice::Applied
        );
        let conflict = deposit_tx(DepositEvent {
            amount: 8,
            ..fixture.deposit.clone()
        });
        assert_eq!(
            advise(&db, &deployments(), &conflict).await.unwrap(),
            Advice::Doomed(Reject::DepositConflict)
        );
        assert_eq!(
            advise(&db, &deployments(), &fixture.admit_tx)
                .await
                .unwrap(),
            Advice::Plausible
        );

        // Advice is a feasibility peek, never exhaustive validation: a
        // deposit fenced by the live registration still reads Plausible, and
        // execution delivers the effect-free rejection.
        let fenced = deposit_tx(DepositEvent {
            id: Sha256::hash(&[b"advice-fenced"]),
            account: identities()[0].key.clone(),
            amount: 1,
        });
        assert_eq!(
            advise(&db, &deployments(), &fenced).await.unwrap(),
            Advice::Plausible
        );
        seal(&db, 2, std::slice::from_ref(&fenced)).await;
        assert_eq!(
            read(
                &db,
                &deposit_key(&deployment(), &Sha256::hash(&[b"advice-fenced"]))
            )
            .await,
            None
        );

        // The admitted close answers Applied for its own bytes.
        seal(&db, 3, std::slice::from_ref(&fixture.admit_tx)).await;
        assert_eq!(
            advise(&db, &deployments(), &fixture.admit_tx)
                .await
                .unwrap(),
            Advice::Applied
        );
    });
}

// --- full example walkthrough end-to-end test ------------------------------

/// Deployment timing policy for the walkthrough deployment.
///
/// The walkthrough runs many client round trips between the registration's
/// inclusion and the certified admission (the corrective payment retry, the
/// receiver's anchored intake, and the close worker's dissemination and
/// admission), and each certified poll advances simulated blocks, so the
/// compiled grid's ten-block runway is too tight for this arc. The admission
/// offset is deployment-chosen at genesis and bounded above by the wallet's
/// withdrawal-deadline horizon (the carried withdrawal must finalize at
/// offset plus duration plus one blocks after the registration's inclusion).
/// Both fields deliberately differ from the compiled grid and the generated
/// genesis defaults: genesis is the timing authority end to end, with
/// execution assigning the deadlines from this policy and the close worker's
/// settlement rehearsal deriving its horizons from the adopted pair. The
/// walkthrough passing under a two-block duration pins that no chain-facing
/// path enforces a compiled pair.
const WALKTHROUGH_TIMING: Timing = Timing {
    admission_offset: 30,
    challenge_duration: 2,
};

/// Custody after epoch 0 settles: four genesis accounts at
/// [`INITIAL_BALANCE`], plus Alice's deposit of ten, minus her claimed
/// withdrawal of three. The end state adds [`UNREPORTED_MINT`].
const WALKTHROUGH_CUSTODY: u64 = 407;

/// The third party's unreported mint to Bob: submitted with no wallet
/// involvement, observed and staged by the operator on its own, and carried
/// in the epoch 1 close.
const UNREPORTED_MINT: u64 = 9;

/// Query server address for one walkthrough validator.
fn walkthrough_query(index: usize) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 7_000 + index as u16))
}

/// Agent-facing RPC address for one walkthrough operator.
fn walkthrough_operator(op: usize) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 7_100 + op as u16))
}

/// Four validators under the production BLS threshold committee plus the
/// production operator stack per configured operator: the SQLite
/// [`Operator`] with the DA-channel close pipeline behind the production RPC
/// service loop, and one driver per operator walking a payment arc with real
/// [`Agent`] wallets whose guarantee-bearing reads all verify through
/// [`Client`]. One operator runs the full scripted-walkthrough arc, and two
/// operators run the concurrent-tenancy arc.
#[derive(Clone)]
struct Walkthrough {
    /// Four consensus validators, then one network identity per operator.
    participants: Vec<ed25519::PublicKey>,
    /// Consensus threshold shares, aligned with the validators.
    shares: Vec<Share>,
    /// The dealt genesis identity every certified read verifies against,
    /// carrying one deployment per operator.
    genesis: Genesis,
    finalized: Vec<Finalized>,
    /// The combined verdict: Ok once every operator's driver succeeded, the
    /// first failure otherwise.
    driver: ClientResult,
    /// Per-operator driver verdicts, folded into `driver` once all are in.
    verdicts: Verdicts,
    /// Alice's deposit id, written by the single-operator driver for the
    /// end-state property.
    deposit: Arc<Mutex<Option<Digest>>>,
}

impl Walkthrough {
    /// Number of consensus validators ahead of the operators.
    const VALIDATORS: usize = 4;

    fn new(operators: usize) -> Self {
        let mut rng = test_rng();
        let signers = (0..Self::VALIDATORS as u64)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let players = Set::from_iter_dedup(signers.iter().map(|signer| signer.public_key()));
        let (identity, dealt) = deal::<MinSig, _, N3f1>(&mut rng, SHARING_MODE, players.clone())
            .expect("the walkthrough deal succeeds");
        let mut participants = players.iter().cloned().collect::<Vec<_>>();
        let shares = participants
            .iter()
            .map(|participant| {
                dealt
                    .get_value(participant)
                    .cloned()
                    .expect("the dealer shares every participant")
            })
            .collect();
        let configured = (0..operators)
            .map(|op| {
                let op = u64::try_from(op).expect("the operator count fits u64");
                participants.push(ed25519::PrivateKey::from_seed(77_777 + op).public_key());
                crate::protocol::Deployment::new(
                    operator_signer(op).public_key(),
                    operator_ack_key(op),
                    accounts(),
                )
            })
            .collect::<Vec<_>>();
        let finalized = (0..participants.len())
            .map(|_| Finalized::default())
            .collect();

        // Validator directory `index` holds clearing key `index` and serves
        // evidence at its query address, exactly as setup writes genesis.
        let validators = (0..Self::VALIDATORS)
            .map(|index| ValidatorEntry {
                clearing: compute_public::<MinSig>(&clearing_private(index).unwrap()),
                query: walkthrough_query(index),
            })
            .collect();
        Self {
            participants,
            shares,
            genesis: Genesis::new(identity, 0, WALKTHROUGH_TIMING, configured, validators),
            finalized,
            driver: ClientResult::default(),
            verdicts: Arc::new(Mutex::new(vec![None; operators])),
            deposit: Arc::default(),
        }
    }

    /// The operator index a participant runs, when it is an operator.
    const fn operator(&self, index: usize) -> Option<usize> {
        if index >= Self::VALIDATORS {
            Some(index - Self::VALIDATORS)
        } else {
            None
        }
    }
}

/// Records one operator driver's verdict and folds the combined result once
/// every driver finished: the first failure wins, otherwise Ok.
fn finish_driver(
    verdicts: &Verdicts,
    combined: &ClientResult,
    op: usize,
    result: Result<(), String>,
) {
    let mut verdicts = verdicts.lock();
    verdicts[op] = Some(result);
    if verdicts.iter().all(Option::is_some) {
        let folded = verdicts
            .iter()
            .enumerate()
            .find_map(|(index, verdict)| {
                let error = verdict.as_ref()?.as_ref().err()?;
                Some(format!("operator {index}: {error}"))
            })
            .map_or(Ok(()), Err);
        *combined.lock() = Some(folded);
    }
}

impl EngineDefinition for Walkthrough {
    type PublicKey = ed25519::PublicKey;
    type Engine = Handle<()>;
    type State = State<Threshold>;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.participants.clone()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (0, TEST_QUOTA), // votes
            (1, TEST_QUOTA), // certificates
            (2, TEST_QUOTA), // resolver
            (3, TEST_QUOTA), // backfill
            (4, TEST_QUOTA), // broadcast
            (5, TEST_QUOTA), // settlement transactions
            (6, TEST_QUOTA), // settlement DA
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            delayed: _,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;

        let validators = self.participants[..Self::VALIDATORS].to_vec();
        let operator = self.operator(index);
        let partition_prefix = operator.map_or_else(
            || format!("validator-{index}"),
            |op| format!("operator-{op}"),
        );
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let db_config = config(&partition_prefix, &context);

        let mut channels = channels.into_iter();
        let vote_network = channels.next().unwrap();
        let certificate_network = channels.next().unwrap();
        let resolver_network = channels.next().unwrap();
        let backfill_network = channels.next().unwrap();
        let broadcast_network = channels.next().unwrap();
        let settlement_tx_network = channels.next().unwrap();
        let settlement_da_network = channels.next().unwrap();

        // The production certificate scheme: validators sign with their dealt
        // threshold shares and the operators verify against the committee
        // identity, so the wallets' [`Client`] verifies real certificates.
        let scheme = if operator.is_some() {
            Threshold::verifier(
                CHAIN_NAMESPACE,
                self.genesis.players().clone(),
                self.genesis.public().clone(),
            )
        } else {
            Threshold::signer(
                CHAIN_NAMESPACE,
                self.genesis.players().clone(),
                self.genesis.public().clone(),
                self.shares[index].clone(),
            )
            .expect("the dealt share matches the walkthrough committee")
        };
        let provider = ConstantProvider::new(scheme.clone());

        // Each operator registers the secondary arrangement at its own
        // successor set id, exactly as in the distributed engine. The
        // simulated network honors only the latest tracked set, so every
        // registration names the whole operator set as secondaries: the
        // validators stay primary and no operator is ever dropped.
        if let Some(op) = operator {
            let mut manager = oracle.manager();
            let primary = Set::from_iter_dedup(validators.iter().cloned());
            let secondary =
                Set::from_iter_dedup(self.participants.iter().skip(Self::VALIDATORS).cloned());
            let _ = commonware_p2p::Manager::track(
                &mut manager,
                1 + op as u64,
                commonware_p2p::TrackedPeers::new(primary, secondary),
            );
        }

        // Marshal resolver.
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(100),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill_network,
        );

        // Buffered broadcast engine.
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: public_key.clone(),
                mailbox_size: NZUsize!(100),
                deque_size: 10,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            },
        );
        broadcast_engine.start(broadcast_network);

        // Prunable archives backing marshal.
        let archive_config = |name: &str| prunable::Config {
            translator: TwoCap,
            key_partition: format!("{partition_prefix}-{name}-key"),
            key_page_cache: page_cache.clone(),
            value_partition: format!("{partition_prefix}-{name}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(10),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        };
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config("finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks =
            prunable::Archive::init(context.child("finalized_blocks"), archive_config("blocks"))
                .await
                .expect("failed to initialize blocks archive");

        // Genesis block shared by every node.
        let genesis_block = Block::genesis(
            validators[0].clone(),
            chain_id(&self.genesis.deployments),
            self.genesis.timestamp,
            initial_sync_target::<deterministic::Context>(),
        );

        let startup = context.child("stateful_startup");
        let plan = SyncPlan::init(&startup, partition_prefix.clone()).await;
        let _ = plan.should_state_sync(false);

        // Marshal actor.
        let (marshal_actor, marshal_mailbox, floor) =
            MarshalActor::<_, Standard<Block>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: provider.clone(),
                    epocher: FixedEpocher::new(EPOCH_LENGTH),
                    start: plan.marshal_start(genesis_block.clone()),
                    partition_prefix: partition_prefix.clone(),
                    mailbox_size: NZUsize!(100),
                    view_retention: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache: page_cache.clone(),
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;

        // Each operator runs the production follower stack, RPC service
        // loop, and close pipeline, plus its own driver.
        if let Some(op) = operator {
            let config = &self.genesis.deployments[op];
            let digest = *config.digest();
            let finalized = self.finalized[index].clone();
            let application: App<Threshold, ()> = App::new(
                genesis_block.clone(),
                WALKTHROUGH_TIMING,
                self.genesis.deployments.clone(),
                finalized.clone(),
            );
            let (stateful_actor, stateful_mailbox) = StatefulActor::init(
                context.child("stateful"),
                StatefulConfig {
                    application,
                    db_config,
                    provider: (),
                    marshal: (marshal_mailbox.clone(), floor),
                    mailbox_size: NZUsize!(100),
                    plan,
                    resolvers: NoopResolver,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(16),
                        apply_batch_size: NZU64!(64),
                        max_outstanding_requests: 8,
                        update_channel_size: NZUsize!(256),
                        max_retained_roots: 8,
                    },
                    prune_config: None,
                },
            );
            let reader_mailbox = stateful_mailbox.clone();
            let reader: StateReader = Arc::new(move |key: StateKey| {
                let mailbox = reader_mailbox.clone();
                Box::pin(async move {
                    let databases = mailbox.subscribe_databases().await;
                    let guard = databases.read().await;
                    guard.get(&key).await.expect("state read must succeed")
                })
            });
            // The deposit observer joins the finalized-block reporter chain,
            // exactly as `node::start` wires it: a deposit-carrying block is
            // acknowledged only after its applied events are durably staged.
            let (observer, mut observations) =
                commonware_actor::mailbox::new(context.child("observations"), NZUsize!(100));
            let marshal_reporters = MonitorReporter::new(
                public_key.clone(),
                monitor,
                Reporters::from((
                    stateful_mailbox.clone(),
                    node::Observer::new(digest, observer),
                )),
            );
            marshal_actor.start(marshal_reporters, buffer, resolver);
            stateful_actor.start();
            node::drain(context.child("vote_drain"), vote_network.1);
            node::drain(context.child("resolver_drain"), resolver_network.1);
            node::drain(context.child("tx_drain"), settlement_tx_network.1);
            node::follow(
                context.child("follow"),
                provider,
                marshal_mailbox.clone(),
                certificate_network.1,
            );

            // The local chain backend and the close pipeline.
            let db = stateful_mailbox.subscribe_databases().await;
            let backend = Node::new(digest, db, finalized.clone(), settlement_tx_network.0);
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (certifier, certify_mailbox) = node::Certifier::new(
                context.child("certifier"),
                node::Config {
                    verifier: protocol.verifier(),
                    chain: backend.clone(),
                    mailbox_size: NZUsize!(100),
                },
            );
            let handle = certifier.start(settlement_da_network);

            // The production operator over its close pipeline, served through
            // the production RPC loop. The listener binds before the driver
            // starts so no wallet call races the service coming up.
            let pipeline = node::Pipeline::new(certify_mailbox, &validators)
                .expect("the walkthrough committee maps to network identities");
            let clearing = operator_signer(u64::try_from(op).expect("the operator index fits u64"));
            let ack = operator_ack_signer(u64::try_from(op).expect("the operator index fits u64"));
            let sqlite = Arc::new(Mutex::new(
                Operator::open_remote(Path::new(":memory:"), NZUsize!(1), pipeline, clearing, ack)
                    .expect("the walkthrough operator opens"),
            ));
            context.child("observer").spawn({
                let mut chain = backend.clone();
                let operator = sqlite.clone();
                move |context| async move {
                    while let Some(observed) = observations.recv().await {
                        observe(&context, &mut chain, &operator, observed)
                            .await
                            .expect("deposit observation stages durably");
                    }
                }
            });
            let address = walkthrough_operator(op);
            let listener = context
                .bind(address)
                .await
                .expect("the operator RPC address binds");
            context.child("operator_rpc").spawn({
                let chain = backend.clone();
                move |context| serve_operator(context, listener, sqlite, chain)
            });

            // One driver per operator: the single-operator engine walks the
            // whole example flow, and the multi-operator engine walks each
            // deployment's payment arc concurrently.
            let verdicts = self.verdicts.clone();
            let combined = self.driver.clone();
            let genesis = self.genesis.clone();
            let deposit = self.deposit.clone();
            let queries: Vec<std::net::SocketAddr> =
                (0..validators.len()).map(walkthrough_query).collect();
            let single = self.genesis.deployments.len() == 1;
            context.child("driver").spawn(move |context| async move {
                let result = if single {
                    Box::pin(walkthrough(context, genesis, address, queries, deposit)).await
                } else {
                    Box::pin(tenant(context, genesis, op, address, queries)).await
                }
                .map_err(|error| format!("{error:#}"));
                finish_driver(&verdicts, &combined, op, result);
            });

            return (
                handle,
                State {
                    marshal: marshal_mailbox,
                    reader,
                    finalized,
                    client: self.driver.clone(),
                },
            );
        }

        // Validators run the full consensus stack plus the sealer and the
        // certified query server.
        let (ingress_actor, ingress_mailbox) = ingress::Actor::new(
            context.child("ingress"),
            ingress::Config {
                mailbox_size: NZUsize!(100),
                capacity: NZUsize!(1_024),
                bytes: NZUsize!(64 * 1024 * 1024),
                seen: NZUsize!(4_096),
                lease: 5,
            },
        );
        ingress_actor.start(settlement_tx_network);

        let finalized = self.finalized[index].clone();
        let application: App<Threshold, ingress::Mailbox> = App::new(
            genesis_block.clone(),
            WALKTHROUGH_TIMING,
            self.genesis.deployments.clone(),
            finalized.clone(),
        );
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                provider: ingress_mailbox.clone(),
                marshal: (marshal_mailbox.clone(), floor),
                mailbox_size: NZUsize!(100),
                plan,
                resolvers: NoopResolver,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
                prune_config: None,
            },
        );
        let reader_mailbox = stateful_mailbox.clone();
        let reader: StateReader = Arc::new(move |key: StateKey| {
            let mailbox = reader_mailbox.clone();
            Box::pin(async move {
                let databases = mailbox.subscribe_databases().await;
                let guard = databases.read().await;
                guard.get(&key).await.expect("state read must succeed")
            })
        });

        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let marshal_reporters = MonitorReporter::new(
            public_key.clone(),
            monitor,
            Reporters::from((stateful_mailbox.clone(), ingress_mailbox.clone())),
        );
        marshal_actor.start(marshal_reporters, buffer, resolver);
        stateful_actor.start();

        // The sealing actor on the DA channel, keyed by the validator's
        // dealt clearing committee key and configured for every operator's
        // deployment.
        let db = stateful_mailbox.subscribe_databases().await;
        let dealers = self
            .participants
            .iter()
            .skip(Self::VALIDATORS)
            .cloned()
            .zip(self.genesis.deployments.iter().cloned())
            .collect();
        let (sealer, sealer_mailbox) = da::Sealer::new(
            context.child("sealer"),
            da::Config {
                scheme: commonware_clearing::bajillion::admission::bls12381::Scheme::signer(
                    committee().unwrap(),
                    clearing_private(index).unwrap(),
                )
                .unwrap(),
                operators: dealers,
                db: db.clone(),
                partition: format!("{partition_prefix}-dealings"),
                validators: self.genesis.validators.clone(),
                fetch_timeout: Duration::from_secs(2),
            },
        );
        sealer.start(settlement_da_network);

        // Certified query server over the applied database, serving evidence
        // from the sealer's retained dealings.
        query::start(
            context.child("query"),
            query::Config {
                address: walkthrough_query(index),
                deployments: self.genesis.deployments.clone(),
                db,
                finalized: finalized.clone(),
                marshal: marshal_mailbox.clone(),
                ingress: ingress_mailbox,
                sealer: Some(sealer_mailbox),
            },
        );

        // Simplex engine.
        let engine = simplex::Engine::new(
            context,
            simplex::Config {
                scheme,
                elector: RoundRobin::<Sha256>::default(),
                blocker: oracle.control(public_key.clone()),
                automaton: deferred.clone(),
                relay: deferred,
                reporter: marshal_mailbox.clone(),
                strategy: Sequential,
                partition: format!("{partition_prefix}-simplex"),
                mailbox_size: NZUsize!(3),
                epoch: Epoch::zero(),
                floor: simplex::config::Floor::Genesis(genesis_block.digest()),
                replay_buffer: IO_BUFFER_SIZE,
                write_buffer: IO_BUFFER_SIZE,
                page_cache,
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_millis(500),
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: simplex::SkipBudget::Participants,
                },
                fetch_timeout: Duration::from_secs(2),
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
            },
        );
        let handle = engine.start(vote_network, certificate_network, resolver_network);

        (
            handle,
            State {
                marshal: marshal_mailbox,
                reader,
                finalized,
                client: self.driver.clone(),
            },
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

/// Serves the production operator RPC loop (the `run_operator` service loop)
/// over one bound listener: decode, run the settlement preconditions through
/// [`prepare_request`] against the operator's own follower node, dispatch
/// synchronously, respond.
async fn serve_operator<L: Listener>(
    context: deterministic::Context,
    mut listener: L,
    operator: Arc<Mutex<Operator>>,
    mut chain: Node<deterministic::Context, TxSender>,
) {
    loop {
        let Ok((_, mut sink, mut stream)) = listener.accept().await else {
            context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
            continue;
        };
        let Ok(request) = rpc::recv_request(&mut stream).await else {
            continue;
        };
        let response = match operator_rpc::decode_request(request) {
            Ok(request) => match prepare_request(&context, &mut chain, &operator, &request).await {
                Ok(Some(response)) => response,
                Ok(None) => operator_rpc::handle_decoded(&mut operator.lock(), request),
                Err(error) => rpc::error_response(format!("{error:#}")),
            },
            Err(error) => rpc::error_response(format!("{error:#}")),
        };
        let _ = rpc::send_response(&mut sink, &response).await;
    }
}

/// Polls the verified balance until the operator's observed credit shows,
/// the wallet's only view of a staged deposit.
async fn observed_balance(
    context: &deterministic::Context,
    agent: &mut Agent,
    chain: &mut Client,
    operator: std::net::SocketAddr,
    expected: u64,
) -> anyhow::Result<()> {
    let mut last = None;
    for _ in 0..EFFECT_ATTEMPTS {
        match agent.balance(context, chain, operator).await {
            Ok(balance) if balance == expected => return Ok(()),
            outcome => last = Some(outcome.map_err(|error| format!("{error:#}"))),
        }
        context.sleep(POLL).await;
    }
    anyhow::bail!("the operator never credited the observed deposit (last read: {last:?})")
}

/// Cuts one epoch through the operator's production close worker and drives
/// it to certified finalization, returning the finish event.
async fn walkthrough_close(
    context: &deterministic::Context,
    agent: &mut Agent,
    operator: std::net::SocketAddr,
) -> anyhow::Result<operator_rpc::CloseFinishedResponse> {
    let close = agent.start_close(context, operator).await?;
    loop {
        match agent.poll_close(context, operator, close.epoch).await? {
            operator_rpc::PollCloseResponse::NoEvent => {
                // The close worker is a real OS thread: the real pause lets it
                // compute between polls, and the short virtual pause lets
                // consensus seal the admission and its challenge window in
                // real blocks without racing the block-height deadlines.
                std::thread::sleep(Duration::from_millis(2));
                context.sleep(Duration::from_millis(10)).await;
            }
            operator_rpc::PollCloseResponse::Finished(finished) => {
                anyhow::ensure!(
                    finished.epoch == close.epoch,
                    "the operator finished another epoch"
                );
                return Ok(finished);
            }
            operator_rpc::PollCloseResponse::Failed { epoch, error } => anyhow::bail!(
                "epoch {epoch} close failed: {}",
                String::from_utf8_lossy(&error)
            ),
        }
    }
}

/// The entire example flow, driven with the production wallets against the
/// running deployment: Alice's deposit, her carried fast-lane withdrawal,
/// her payment to Bob with Bob's anchored intake gating acceptance before
/// the close is cut, the distributed close of epoch 0 through real blocks to
/// certified finalization, Alice's claim against the certified release
/// record, Bob's reconciliation of epoch 0, the successor payment that
/// registers epoch 1, its close, and the settled end state, every
/// guarantee-bearing read verified through the light client.
async fn walkthrough(
    context: deterministic::Context,
    genesis: Genesis,
    operator: std::net::SocketAddr,
    queries: Vec<std::net::SocketAddr>,
    deposit_slot: Arc<Mutex<Option<Digest>>>,
) -> anyhow::Result<()> {
    let mut alice = Agent::new(0)?;
    let mut bob = Agent::new(1)?;
    let mut alice_chain = Client::new(
        &genesis,
        deployment(),
        queries.clone(),
        context.child("alice_rng"),
    )?;
    let mut bob_chain = Client::new(&genesis, deployment(), queries, context.child("bob_rng"))?;

    // Alice deposits in one step: the Deposit transaction completes on the
    // certified custody record alone. The operator is never told: its
    // follower observes the finalized record and stages the credit itself,
    // which the verified balance poll shows.
    let deposit = alice.deposit(&context, &mut alice_chain, 10).await?;
    anyhow::ensure!(deposit.amount == 10, "custody was taken for another amount");
    *deposit_slot.lock() = Some(deposit.id);
    observed_balance(&context, &mut alice, &mut alice_chain, operator, 110).await?;

    // Alice authorizes the fast-lane withdrawal the operator carries in the
    // close. It must precede her first payment: the first receipt registers
    // the epoch on the chain, which permanently commits the boundary the
    // close must reproduce.
    let withdrawal = NonZeroU64::new(3).expect("the withdrawal amount is positive");
    match alice
        .withdraw(
            &context,
            &mut alice_chain,
            operator,
            WithdrawalAction::Amount(withdrawal),
        )
        .await?
    {
        WithdrawalOutcome::Applied { epoch, request } => {
            anyhow::ensure!(epoch == 0, "the withdrawal staged a foreign epoch");
            anyhow::ensure!(
                request.account() == &alice.account(),
                "the operator staged another account's withdrawal"
            );
        }
        WithdrawalOutcome::Signed { error, .. } => {
            anyhow::bail!("the operator never carried the signed withdrawal: {error:#}")
        }
    }

    // Alice pays Bob optimistically. The first receipt registers epoch 0 on
    // the chain (the operator's service loop completes on the certified
    // registration record and adopts the assigned deadlines), the wallet
    // re-signs once from the corrective rejection, and the acceptance passes
    // the certified anchor gate before the verified receipts are held.
    let payment = match alice
        .pay(&context, &mut alice_chain, operator, &[(1, 5)])
        .await?
    {
        PaymentOutcome::Accepted(payment) => *payment,
        PaymentOutcome::CommittedUnheld { epoch, .. } => {
            anyhow::bail!("epoch {epoch} payment committed without receipts")
        }
    };
    anyhow::ensure!(payment.epoch == 0, "the payment landed in a foreign epoch");
    anyhow::ensure!(payment.total == 5, "the payment debited another total");
    anyhow::ensure!(
        payment.acceptance.entries.len() == 1 && alice.receipt_count() == 1,
        "the payment's verified receipt is not held durably"
    );
    let invoice = Sha256::hash(&[payment.acceptance.ack.body().encode().as_ref()]);

    // Bob's receiver intake fetches, verifies, and settlement-anchors the
    // pair, and his acceptance gate answers from the durably held evidence
    // BEFORE the close is cut.
    bob.intake_incoming(&context, &mut bob_chain, operator)
        .await?;
    let held = bob.incoming();
    anyhow::ensure!(
        held.total == 5 && held.count == 1,
        "the receiver ledger does not hold the verified pair"
    );
    let credit = bob
        .paid(&alice.account(), &invoice)?
        .context("the receiver gate found no held evidence for the invoice")?;
    anyhow::ensure!(
        credit.amount == 5 && credit.epoch == 0,
        "the receiver gate answered another credit"
    );

    // The operator cuts and closes epoch 0: dissemination, sealing, votes,
    // the exact-quorum certificate, the certified admission, and the
    // challenge window in real blocks to certified finalization.
    let finished = walkthrough_close(&context, &mut alice, operator).await?;
    anyhow::ensure!(finished.epoch == 0, "the close finished a foreign epoch");
    anyhow::ensure!(
        finished.payout_total == 0,
        "the close reserved an external payout"
    );
    anyhow::ensure!(finished.rows > 0, "the close settled no account rows");
    let settled = alice_chain.status(&context).await?;
    anyhow::ensure!(
        settled.last_finalized == Some(0) && !settled.hard_faulted,
        "epoch 0 did not certifiably finalize"
    );
    anyhow::ensure!(
        settled.custody == WALKTHROUGH_CUSTODY && settled.claimable == 3,
        "finalization left unexpected custody {} and claimable {}",
        settled.custody,
        settled.claimable
    );

    // Alice claims the carried withdrawal against the certified release
    // record at the finalized batch's exact position.
    let release = alice
        .claim_withdrawal(&context, &mut alice_chain, operator)
        .await?;
    anyhow::ensure!(
        release.amount == 3 && release.destination.as_ref() == b"Alice",
        "settlement released another withdrawal"
    );
    let claimed = alice_chain.status(&context).await?;
    anyhow::ensure!(
        claimed.custody == WALKTHROUGH_CUSTODY && claimed.claimable == 0,
        "the claim left unexpected custody {} and claimable {}",
        claimed.custody,
        claimed.claimable
    );

    // Bob reconciles epoch 0 against the certified admitted roots: every
    // held credit is evidence-backed, marked RECONCILED durably.
    let summary = bob.reconcile(&context, &mut bob_chain, operator).await?;
    anyhow::ensure!(
        summary.reconciled == vec![0]
            && summary.convicted.is_empty()
            && summary.unenforceable.is_empty()
            && summary.withheld.is_empty(),
        "epoch 0 did not reconcile cleanly: {summary:?}"
    );
    anyhow::ensure!(
        bob.last_reconciled_epoch() == Some(0),
        "the RECONCILED mark is not durable"
    );

    // The old griefing lever is gone: a third party mints custody for Bob at
    // settlement with NO wallet involvement and no operator report. The
    // operator's follower observes the finalized record, stages the credit
    // on its own, and the next close's boundary carries it.
    let unreported = DepositEvent {
        id: Sha256::hash(&[b"walkthrough-unreported-mint"]),
        account: bob.account(),
        amount: UNREPORTED_MINT,
    };
    alice_chain
        .deliver(
            &context,
            &SettlementTx::Deposit(DepositRequest {
                deployment: deployment(),
                event: unreported.clone(),
            }),
        )
        .await?;
    let mut recorded = false;
    for _ in 0..EFFECT_ATTEMPTS {
        if alice_chain
            .deposit(&context, unreported.id)
            .await
            .ok()
            .flatten()
            .as_ref()
            == Some(&unreported)
        {
            recorded = true;
            break;
        }
        context.sleep(POLL).await;
    }
    anyhow::ensure!(recorded, "the unreported mint earned no custody record");
    observed_balance(
        &context,
        &mut bob,
        &mut bob_chain,
        operator,
        105 + UNREPORTED_MINT,
    )
    .await?;

    // The successor payment registers epoch 1 at its first receipt, and
    // Bob's intake holds its pair before that close is cut.
    let successor = match alice
        .pay(&context, &mut alice_chain, operator, &[(1, 1)])
        .await?
    {
        PaymentOutcome::Accepted(payment) => *payment,
        PaymentOutcome::CommittedUnheld { epoch, .. } => {
            anyhow::bail!("epoch {epoch} successor payment committed without receipts")
        }
    };
    anyhow::ensure!(
        successor.epoch == 1 && alice.receipt_count() == 2,
        "the successor payment did not land in epoch 1"
    );
    bob.intake_incoming(&context, &mut bob_chain, operator)
        .await?;
    let held = bob.incoming();
    anyhow::ensure!(
        held.total == 6 && held.count == 2,
        "the receiver ledger does not hold both verified pairs"
    );

    // Close epoch 1 inside its admission runway and reconcile it: nothing
    // registers afterwards, so the deployment idles safely.
    let finished = walkthrough_close(&context, &mut alice, operator).await?;
    anyhow::ensure!(finished.epoch == 1, "the close finished a foreign epoch");
    anyhow::ensure!(
        finished.payout_total == 0,
        "the empty-boundary close reserved an external payout"
    );
    let summary = bob.reconcile(&context, &mut bob_chain, operator).await?;
    anyhow::ensure!(
        summary.reconciled == vec![1],
        "epoch 1 did not reconcile cleanly: {summary:?}"
    );
    anyhow::ensure!(
        bob.last_reconciled_epoch() == Some(1),
        "the RECONCILED mark did not advance"
    );

    // The walkthrough's end state, as certified reads: both epochs
    // finalized, no live registration, custody and claimable settled, the
    // custody records still proving both deposits, and no fault.
    let mut retired = false;
    for _ in 0..EFFECT_ATTEMPTS {
        if alice_chain.registration(&context).await?.is_none() {
            retired = true;
            break;
        }
        context.sleep(POLL).await;
    }
    anyhow::ensure!(retired, "a live registration outlived the walkthrough");
    let end = alice_chain.status(&context).await?;
    anyhow::ensure!(
        end.last_finalized == Some(1)
            && end.custody == WALKTHROUGH_CUSTODY + UNREPORTED_MINT
            && end.claimable == 0
            && !end.hard_faulted,
        "the end state did not settle: {end:?}"
    );
    for epoch in [0, 1] {
        let admitted = alice_chain
            .admitted(&context, epoch)
            .await?
            .context("a finalized epoch lost its admitted record")?;
        anyhow::ensure!(admitted.finalized, "epoch {epoch} is not finalized");
    }
    anyhow::ensure!(
        alice_chain.deposit(&context, deposit.id).await? == Some(deposit),
        "the certified custody record does not prove the deposit"
    );
    anyhow::ensure!(
        alice_chain.deposit(&context, unreported.id).await? == Some(unreported),
        "the certified custody record does not prove the unreported mint"
    );
    anyhow::ensure!(
        alice_chain.fault(&context).await?.is_none(),
        "the walkthrough left a fault record"
    );

    // Alice's balances: the verified head read against the certified state
    // root. Initial 100, plus the deposit of 10, minus the withdrawal of 3
    // and the payments of 5 and 1. Bob holds his credits plus the observed
    // unreported mint.
    let balance = alice.balance(&context, &mut alice_chain, operator).await?;
    anyhow::ensure!(balance == 101, "Alice's verified balance is {balance}");
    let balance = bob.balance(&context, &mut bob_chain, operator).await?;
    anyhow::ensure!(
        balance == 106 + UNREPORTED_MINT,
        "Bob's verified balance is {balance}"
    );
    Ok(())
}

/// One tenant deployment's concurrent arc, driven against its own operator
/// while the other operators run theirs on the same chain: Alice's deposit
/// observed into the operator's staging, a payment to Bob whose first
/// receipt registers epoch 0, Bob's anchored intake and acceptance gate, the
/// distributed close of epoch 0 through real blocks, the successor payment
/// and close of epoch 1, Bob's reconciliation of both epochs, and
/// deployment-scoped certified reads: this deployment's records are absent
/// under the other deployment's scope.
async fn tenant(
    context: deterministic::Context,
    genesis: Genesis,
    op: usize,
    operator: std::net::SocketAddr,
    queries: Vec<std::net::SocketAddr>,
) -> anyhow::Result<()> {
    let config = &genesis.deployments[op];
    let scoped = *config.digest();
    let mut alice = Agent::new_for(0, config.operator.clone())?;
    let mut bob = Agent::new_for(1, config.operator.clone())?;
    let mut alice_chain = Client::new(
        &genesis,
        scoped,
        queries.clone(),
        context.child("alice_rng"),
    )?;
    let mut bob_chain = Client::new(&genesis, scoped, queries.clone(), context.child("bob_rng"))?;

    // Alice's deposit names this deployment, completes on its certified
    // custody record, and the operator's follower stages only its own
    // deployment's finalized deposits.
    let deposit = alice.deposit(&context, &mut alice_chain, 10).await?;
    anyhow::ensure!(deposit.amount == 10, "custody was taken for another amount");
    observed_balance(&context, &mut alice, &mut alice_chain, operator, 110).await?;

    // Epoch 0: the payment's first receipt registers this deployment's
    // epoch on the shared chain, and Bob gates acceptance on his durably
    // held, settlement-anchored pair before the close is cut.
    let payment = match alice
        .pay(&context, &mut alice_chain, operator, &[(1, 5)])
        .await?
    {
        PaymentOutcome::Accepted(payment) => *payment,
        PaymentOutcome::CommittedUnheld { epoch, .. } => {
            anyhow::bail!("epoch {epoch} payment committed without receipts")
        }
    };
    anyhow::ensure!(payment.epoch == 0, "the payment landed in a foreign epoch");
    let invoice = Sha256::hash(&[payment.acceptance.ack.body().encode().as_ref()]);
    bob.intake_incoming(&context, &mut bob_chain, operator)
        .await?;
    let credit = bob
        .paid(&alice.account(), &invoice)?
        .context("the receiver gate found no held evidence for the invoice")?;
    anyhow::ensure!(
        credit.amount == 5 && credit.epoch == 0,
        "the receiver gate answered another credit"
    );
    let finished = walkthrough_close(&context, &mut alice, operator).await?;
    anyhow::ensure!(finished.epoch == 0, "the close finished a foreign epoch");
    let summary = bob.reconcile(&context, &mut bob_chain, operator).await?;
    anyhow::ensure!(
        summary.reconciled == vec![0] && summary.convicted.is_empty(),
        "epoch 0 did not reconcile cleanly: {summary:?}"
    );

    // Epoch 1 interleaves with the other tenants' epochs across blocks.
    let successor = match alice
        .pay(&context, &mut alice_chain, operator, &[(1, 1)])
        .await?
    {
        PaymentOutcome::Accepted(payment) => *payment,
        PaymentOutcome::CommittedUnheld { epoch, .. } => {
            anyhow::bail!("epoch {epoch} successor payment committed without receipts")
        }
    };
    anyhow::ensure!(
        successor.epoch == 1,
        "the successor payment did not land in epoch 1"
    );
    bob.intake_incoming(&context, &mut bob_chain, operator)
        .await?;
    let finished = walkthrough_close(&context, &mut alice, operator).await?;
    anyhow::ensure!(finished.epoch == 1, "the close finished a foreign epoch");
    let summary = bob.reconcile(&context, &mut bob_chain, operator).await?;
    anyhow::ensure!(
        summary.reconciled == vec![1],
        "epoch 1 did not reconcile cleanly: {summary:?}"
    );

    // The settled end state, as certified reads scoped to this deployment.
    let end = alice_chain.status(&context).await?;
    anyhow::ensure!(
        end.deployment == scoped,
        "the certified status names another deployment"
    );
    anyhow::ensure!(
        end.last_finalized == Some(1)
            && end.custody == 410
            && end.claimable == 0
            && !end.hard_faulted,
        "the end state did not settle: {end:?}"
    );
    anyhow::ensure!(
        alice_chain.deposit(&context, deposit.id).await? == Some(deposit.clone()),
        "the certified custody record does not prove the deposit"
    );

    // Certified reads are deployment-scoped: one logical lookup (the epoch-0
    // anchor) resolves under each deployment's own key to that deployment's
    // own certified record. The anchor folds the deployment digest, so the
    // two proven values can never coincide. The other tenant runs
    // concurrently, so its anchor is polled within the shared effect budget.
    let other = *genesis.deployments[(op + 1) % genesis.deployments.len()].digest();
    let mut foreign = Client::new(&genesis, other, queries, context.child("foreign_rng"))?;
    let mine = alice_chain
        .anchor(&context, 0)
        .await?
        .context("this deployment's epoch-0 anchor is missing")?;
    let mut theirs = None;
    for _ in 0..EFFECT_ATTEMPTS {
        if let Ok(Some(anchor)) = foreign.anchor(&context, 0).await {
            theirs = Some(anchor);
            break;
        }
        context.sleep(POLL).await;
    }
    let theirs = theirs.context("the other deployment's epoch-0 anchor never appeared")?;
    anyhow::ensure!(
        mine != theirs,
        "two deployment scopes served one anchor record"
    );
    let status = foreign.status(&context).await?;
    anyhow::ensure!(
        status.deployment == other,
        "the foreign-scoped status names the wrong deployment"
    );
    Ok(())
}

/// Exit once the walkthrough driver finished and, on success, every node's
/// applied state finalized epoch 1, so the end-state property reads a
/// settled deployment everywhere.
#[derive(Clone)]
struct WalkthroughDone {
    /// Every configured deployment must reach epoch 1 on every node.
    deployments: Vec<Digest>,
}

impl ExitCondition<ed25519::PublicKey, State<Threshold>> for WalkthroughDone {
    fn name(&self) -> &str {
        "walkthrough done and epoch 1 finalized everywhere"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State<Threshold>],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let verdict = states.first().and_then(|state| state.client.lock().clone());
            match verdict {
                None => Ok(false),

                // A failed driver exits immediately: ClientSucceeded reports it.
                Some(Err(_)) => Ok(true),
                Some(Ok(())) => {
                    let mut settled = 0;
                    for state in states {
                        let mut done = true;
                        for scoped in &self.deployments {
                            if !matches!(
                                (state.reader)(status_key(scoped)).await,
                                Some(Record::Status(status)) if status.last_finalized == Some(1)
                            ) {
                                done = false;
                                break;
                            }
                        }
                        if done {
                            settled += 1;
                        }
                    }
                    Ok(settled >= target_count)
                }
            }
        })
    }
}

/// Every node settled the walkthrough end state.
#[derive(Clone)]
struct WalkthroughSettled {
    deposit: Arc<Mutex<Option<Digest>>>,
}

impl Property<ed25519::PublicKey, State<Threshold>> for WalkthroughSettled {
    fn name(&self) -> &str {
        "walkthrough settled on every node"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State<Threshold>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(deposit) = *self.deposit.lock() else {
                return Err("the driver recorded no deposit id".into());
            };
            for state in states {
                let status = match (state.reader)(status_key(&deployment())).await {
                    Some(Record::Status(status)) => status,
                    record => return Err(format!("expected a status record, found {record:?}")),
                };
                if status.last_finalized != Some(1) {
                    return Err(format!(
                        "epoch 1 did not finalize: {:?}",
                        status.last_finalized
                    ));
                }
                if status.custody != WALKTHROUGH_CUSTODY + UNREPORTED_MINT
                    || status.claimable != 0
                    || status.hard_faulted
                {
                    return Err(format!(
                        "unexpected settled balances: custody {} claimable {} faulted {}",
                        status.custody, status.claimable, status.hard_faulted
                    ));
                }
                if (state.reader)(registration_key(&deployment()))
                    .await
                    .is_some()
                {
                    return Err("a live registration survived the walkthrough".into());
                }
                if !matches!(
                    (state.reader)(deposit_key(&deployment(), &deposit)).await,
                    Some(Record::Deposit(_))
                ) {
                    return Err("the settled deposit record is missing".into());
                }
                if (state.reader)(fault_key(&deployment())).await.is_some() {
                    return Err("the walkthrough left a fault record".into());
                }
                for epoch in [0, 1] {
                    if !matches!(
                        (state.reader)(admitted_key(&deployment(), epoch)).await,
                        Some(Record::Admitted(admitted)) if admitted.finalized
                    ) {
                        return Err(format!("epoch {epoch} is not admitted and finalized"));
                    }
                }
                if state.finalized.latest().is_none() {
                    return Err("the finalized index is empty".into());
                }
            }
            Ok(())
        })
    }
}

/// Every node settled every tenant deployment's end state, each scoped to
/// its own records: two epochs finalized, custody holding the deposit, no
/// live registration, and no fault.
#[derive(Clone)]
struct TenantsSettled {
    deployments: Vec<Digest>,
}

impl Property<ed25519::PublicKey, State<Threshold>> for TenantsSettled {
    fn name(&self) -> &str {
        "every tenant deployment settled on every node"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State<Threshold>],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                for scoped in &self.deployments {
                    let status = match (state.reader)(status_key(scoped)).await {
                        Some(Record::Status(status)) => status,
                        record => {
                            return Err(format!("expected a status record, found {record:?}"));
                        }
                    };
                    if status.deployment != *scoped {
                        return Err("a status record names another deployment".into());
                    }
                    if status.last_finalized != Some(1) {
                        return Err(format!(
                            "epoch 1 did not finalize: {:?}",
                            status.last_finalized
                        ));
                    }
                    if status.custody != 410 || status.claimable != 0 || status.hard_faulted {
                        return Err(format!(
                            "unexpected settled balances: custody {} claimable {} faulted {}",
                            status.custody, status.claimable, status.hard_faulted
                        ));
                    }
                    if (state.reader)(registration_key(scoped)).await.is_some() {
                        return Err("a live registration survived the tenant arc".into());
                    }
                    if (state.reader)(fault_key(scoped)).await.is_some() {
                        return Err("the tenant arc left a fault record".into());
                    }
                    for epoch in [0, 1] {
                        if !matches!(
                            (state.reader)(admitted_key(scoped, epoch)).await,
                            Some(Record::Admitted(admitted)) if admitted.finalized
                        ) {
                            return Err(format!("epoch {epoch} is not admitted and finalized"));
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

#[test]
fn example_flow_end_to_end_onchain() {
    let engine = Walkthrough::new(1);
    let deposit = engine.deposit.clone();
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(WalkthroughDone {
            deployments: vec![deployment()],
        })
        .property(ClientSucceeded)
        .property(WalkthroughSettled { deposit })
        .property(Monotonic)
        .run()
        .unwrap();
}

/// THE concurrent-tenancy pin: two operators drive interleaved epochs on one
/// chain (registrations, closes, certifications, and finalizations
/// interleaving across blocks), agents on each deployment complete payments
/// and receiver gates against their own operator, and every certified read
/// is deployment-scoped.
#[test]
fn two_deployments_run_concurrently() {
    let engine = Walkthrough::new(2);
    let scoped = engine
        .genesis
        .deployments
        .iter()
        .map(|configured| *configured.digest())
        .collect::<Vec<_>>();
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(WalkthroughDone {
            deployments: scoped.clone(),
        })
        .property(ClientSucceeded)
        .property(TenantsSettled {
            deployments: scoped,
        })
        .property(Monotonic)
        .run()
        .unwrap();
}
