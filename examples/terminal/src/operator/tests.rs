use super::*;
use crate::{
    chain::{
        client::{self, Chain as ChainBackend, Env},
        harness,
        ingress::Submission,
        light::Verified,
        node,
        query::{Lookup, ReadRequest},
        state::{
            AdmittedRootsResponse, Record, RegistrationRecord, StatusRecord, WithdrawalResponse,
            admitted_key, deposit_key, registration_key, status_key, withdrawal_key,
            withdrawal_release_key,
        },
        tx::{AdmitRequest, QueueWithdrawalRequest, SettlementTx, WithdrawalClaimRequest},
    },
    protocol::{INITIAL_BALANCE, deployment},
};
use commonware_clearing::bajillion::{qmdb::StateOpening, transition::WithdrawalClaim};
use commonware_cryptography::ed25519;
use commonware_p2p::utils::mocks::inert_channel;
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::TestRng;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("commonware-terminal-{}-{id}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("operator.sqlite");
        Self { directory, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn operator() -> Operator {
    Operator::in_memory(NonZeroUsize::new(2).unwrap()).unwrap()
}

#[test]
fn virtual_credit_to_fresh_key_survives_retry_restart_and_close() {
    let database = TempDatabase::new();
    let recipient = Wallet::from_seed("Fresh", 9_999);
    let key = recipient.public_key();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(operator.store.current_account(&key).unwrap().is_none());
    let (send, entries) = operator.sign_send(0, &[(key.clone(), 25)]).unwrap();
    let accepted = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    assert_eq!(operator.store.current_liability().unwrap(), 400);
    assert!(operator.payment_head(&key).is_err());
    let empty = Endpoint {
        cumulative_debit: 0,
        seq: 0,
        entries: vec![],
    };
    let (early, early_entries) = sign_send_at(
        operator.registration.context.payment(),
        &recipient,
        &empty,
        &[(operator.wallets[1].public_key(), 1)],
    )
    .unwrap();
    assert!(operator.accept_send(early, early_entries).is_err());
    drop(operator);

    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let replay = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    assert_eq!(replay.acceptance, accepted.acceptance);
    assert_eq!(operator.store.current_liability().unwrap(), 400);
    assert!(operator.payment_head(&key).is_err());
    let result = operator.complete_close(13).unwrap();
    assert_eq!(operator.payment_head(&key).unwrap().balance, 25);
    assert_eq!(
        operator
            .balances
            .opening(1, &key)
            .unwrap()
            .verify::<Sha256>(&result.roots.successor)
            .unwrap()
            .get(),
        25
    );
    assert_eq!(
        operator
            .accept_send(send, entries)
            .unwrap()
            .into_accepted()
            .acceptance,
        accepted.acceptance
    );
    drop(operator);

    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(operator.balances.startup_work().unwrap(), (vec![], vec![]));
    assert_eq!(operator.payment_head(&key).unwrap().balance, 25);
    let (send, entries) = sign_send_at(
        operator.registration.context.payment(),
        &recipient,
        &empty,
        &[(operator.wallets[1].public_key(), 7)],
    )
    .unwrap();
    operator.accept_send(send, entries).unwrap();
    assert_eq!(
        operator
            .store
            .current_account(&key)
            .unwrap()
            .unwrap()
            .current,
        18
    );
}

#[test]
fn virtual_credits_conserve_the_multilateral_balance_example() {
    let identities = identities()[..2].to_vec();
    let accounts = identities
        .iter()
        .zip([100, 40])
        .map(|(identity, balance)| Account {
            key: identity.key.clone(),
            balance,
        })
        .collect::<Vec<_>>();
    let mut operator = Operator::from_store(
        Store::open_configured(Path::new(":memory:"), &identities, &accounts).unwrap(),
        identities,
        Protocol::new(NonZeroUsize::MIN).unwrap(),
        None,
        &accounts,
        None,
        4096,
    )
    .unwrap();
    let c = Wallet::from_seed("Fresh C", 10_001).public_key();
    let d = Wallet::from_seed("Fresh D", 10_002).public_key();
    for (payer, recipient, amount) in [
        (0, operator.wallets[1].public_key(), 20),
        (0, c.clone(), 10),
        (1, c.clone(), 5),
        (1, d.clone(), 8),
    ] {
        let (send, entries) = operator.sign_send(payer, &[(recipient, amount)]).unwrap();
        operator.accept_send(send, entries).unwrap();
    }
    assert_eq!(operator.store.current_liability().unwrap(), 140);
    operator.complete_close(14).unwrap();
    for (key, balance) in [
        (accounts[0].key.clone(), 70),
        (accounts[1].key.clone(), 47),
        (c, 15),
        (d, 8),
    ] {
        assert_eq!(operator.payment_head(&key).unwrap().balance, balance);
    }
}

#[test]
fn observed_batch_duplicates_stage_once_and_replay_after_restart() {
    let database = TempDatabase::new();
    let first = DepositEvent {
        id: Sha256::hash(&[b"observed-batch-first"]),
        account: wallets()[0].public_key(),
        amount: 7,
    };
    let second = DepositEvent {
        id: Sha256::hash(&[b"observed-batch-second"]),
        account: wallets()[1].public_key(),
        amount: 3,
    };
    let events = [first.clone(), second.clone(), first.clone(), second.clone()];
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let staged = operator.observe(&events).unwrap();
    assert_eq!(
        staged.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![first.id, second.id]
    );
    let context = operator.registration.context.payment().clone();
    assert_eq!(
        operator.payment_head(&first.account).unwrap().balance,
        INITIAL_BALANCE + first.amount
    );
    assert_eq!(
        operator.payment_head(&second.account).unwrap().balance,
        INITIAL_BALANCE + second.amount
    );
    drop(operator);
    let mut recovered = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(recovered.observe(&events).unwrap().is_empty());
    assert_eq!(recovered.registration.context.payment(), &context);
    assert_eq!(recovered.store.load_current().unwrap().deposits.len(), 2);
}

#[test]
fn observed_batch_conflicts_reject_before_mutation_in_both_orders() {
    let first = DepositEvent {
        id: Sha256::hash(&[b"observed-batch-conflict"]),
        account: wallets()[0].public_key(),
        amount: 7,
    };
    let conflict = DepositEvent {
        amount: 8,
        ..first.clone()
    };
    for events in [[first.clone(), conflict.clone()], [conflict, first.clone()]] {
        let mut operator = operator();
        let before = operator.registration.context.payment().clone();
        assert!(operator.observe(&events).is_err());
        operator.ensure_store_usable().unwrap();
        assert_eq!(operator.registration.context.payment(), &before);
        assert_eq!(operator.store.load_current().unwrap().deposits.len(), 0);
        assert_eq!(
            operator.payment_head(&first.account).unwrap().balance,
            INITIAL_BALANCE
        );
    }
}

#[test]
fn withdrawal_intake_rejects_non_native_destinations_without_mutation() {
    let mut operator = operator();
    let wallet = wallets().remove(0);
    let account = wallet.public_key();
    let before = operator.payment_head(&account).unwrap();
    let mut suffixed_key = eve_identity().key.encode().to_vec();
    suffixed_key.push(0);
    for destination in [
        Bytes::from_static(b"Alice"),
        Bytes::new(),
        Bytes::from(vec![0; 31]),
        Bytes::from(suffixed_key),
    ] {
        let request = SignedWithdrawal::sign(
            deployment(),
            operator
                .balances
                .root(operator.registration.context.payment().epoch())
                .unwrap()
                .digest,
            destination,
            amount(3),
            50,
            wallet.signer(),
        );
        request.verify_signature().unwrap();
        assert!(
            operator.apply_withdrawal(request).is_err(),
            "operator accepted a destination the native settlement cannot credit"
        );
        let after = operator.payment_head(&account).unwrap();
        assert_eq!(after.context, before.context);
        assert_eq!(after.balance, before.balance);
        assert!(
            operator
                .store
                .load_current()
                .unwrap()
                .withdrawals
                .is_empty()
        );
        assert!(!operator.store.has_current_work().unwrap());
        assert!(operator.fault().is_none());
    }
}

#[test]
fn withdrawal_intake_accepts_arbitrary_native_destination() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let wallet = wallets().remove(0);
        let destination = Wallet::from_seed("Arbitrary withdrawal", 98_765_432).public_key();
        assert_ne!(destination, eve_identity().key);
        assert!(
            !operator
                .identities
                .iter()
                .any(|identity| identity.key == destination)
        );
        let request = SignedWithdrawal::sign(
            deployment(),
            operator
                .balances
                .root(operator.registration.context.payment().epoch())
                .unwrap()
                .digest,
            destination.encode(),
            amount(3),
            50,
            wallet.signer(),
        );
        let applied = operator.apply_withdrawal(request.clone()).unwrap();
        assert_eq!(applied.action, amount(3));
        assert_eq!(
            operator.apply_withdrawal(request).unwrap().epoch,
            applied.epoch
        );
        assert!(chain.try_register(&mut operator).await.is_some());
    });
}

#[test]
fn configured_operator_balances_survive_reopen() {
    let identities = identities();
    for balances in [[0, 0, 0, 0], [0, 7, 19, 3]] {
        let database = TempDatabase::new();
        let configured = identities
            .iter()
            .zip(balances)
            .map(|(identity, balance)| Account {
                key: identity.key.clone(),
                balance,
            })
            .collect::<Vec<_>>();
        for _ in 0..2 {
            let store = Store::open_configured(database.path(), &identities, &configured).unwrap();
            let operator = Operator::from_store(
                store,
                identities.clone(),
                Protocol::new(NonZeroUsize::MIN).unwrap(),
                None,
                &configured,
                None,
                4 * 1024,
            )
            .unwrap();
            assert_eq!(
                operator.store.current_liability().unwrap(),
                balances.into_iter().sum::<u64>()
            );
            assert_eq!(
                operator
                    .balances
                    .root(operator.registration.context.payment().epoch())
                    .unwrap(),
                operator.genesis_root
            );
            for (identity, balance) in identities.iter().zip(balances) {
                if balance == 0 {
                    assert!(operator.payment_head(&identity.key).is_err());
                    continue;
                }
                let head = operator.payment_head(&identity.key).unwrap();
                assert_eq!(head.balance, balance);
                assert_eq!(head.opening.balance.get(), balance);
                assert_eq!(head.root, operator.genesis_root);
            }
        }
    }
}

#[test]
fn empty_deployment_funding_closes_before_positive_payment_evidence() {
    let database = TempDatabase::new();
    let identities = identities();
    let configured = identities
        .iter()
        .map(|identity| Account {
            key: identity.key.clone(),
            balance: 0,
        })
        .collect::<Vec<_>>();
    let store = Store::open_configured(database.path(), &identities, &configured).unwrap();
    let mut operator = Operator::from_store(
        store,
        identities.clone(),
        Protocol::new(NonZeroUsize::MIN).unwrap(),
        None,
        &configured,
        None,
        4096,
    )
    .unwrap();
    let account = identities[0].key.clone();
    let empty = operator.genesis_root;
    operator
        .observe(&[DepositEvent {
            id: Sha256::hash(&[b"first-positive-balance"]),
            account: account.clone(),
            amount: 20,
        }])
        .unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 20);
    assert!(operator.payment_head(&account).is_err());
    assert_eq!(operator.balances.root(0).unwrap(), empty);
    let result = operator.complete_close(17).unwrap();
    let head = operator.payment_head(&account).unwrap();
    assert_eq!(
        head.opening
            .verify::<Sha256>(&result.roots.successor)
            .unwrap()
            .get(),
        20
    );
    assert!(operator.balances.opening(0, &account).is_err());
    drop(operator);
    let store = Store::open_configured(database.path(), &identities, &configured).unwrap();
    let operator = Operator::from_store(
        store,
        identities,
        Protocol::new(NonZeroUsize::MIN).unwrap(),
        None,
        &configured,
        None,
        4096,
    )
    .unwrap();
    assert_eq!(operator.balances.startup_work().unwrap(), (vec![], vec![]));
    assert_eq!(operator.payment_head(&account).unwrap().balance, 20);
}

#[test]
fn initially_unfunded_recipient_becomes_virtual_through_close_and_reopen() {
    let database = TempDatabase::new();
    let identities = identities();
    let accounts = identities
        .iter()
        .zip([0, 7, 19, 3])
        .map(|(identity, balance)| Account {
            key: identity.key.clone(),
            balance,
        })
        .collect::<Vec<_>>();
    let open = || {
        Operator::from_store(
            Store::open_configured(database.path(), &identities, &accounts).unwrap(),
            identities.clone(),
            Protocol::new(NonZeroUsize::MIN).unwrap(),
            None,
            &accounts,
            None,
            4 * 1024,
        )
        .unwrap()
    };
    let mut operator = open();
    operator.pay(1, 0, 5).unwrap();
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
    assert!(operator.payment_head(&identities[0].key).is_err());
    let result = operator.complete_close(1).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 29);
    assert_eq!(
        operator
            .balances
            .opening(1, &identities[0].key)
            .unwrap()
            .verify::<Sha256>(&result.roots.successor)
            .unwrap()
            .get(),
        5
    );
    drop(operator);
    let operator = open();
    assert_eq!(
        operator.payment_head(&identities[0].key).unwrap().balance,
        5
    );
    assert_eq!(operator.store.current_liability().unwrap(), 29);
}

#[test]
fn gross_payment_limit_is_checked_before_acknowledgment() {
    let mut operator = operator();
    let amount = crate::protocol::SQLITE_U64_MAX - 400;
    operator.deposit(0, amount).unwrap();
    operator.pay(0, 1, amount).unwrap();
    let error = operator
        .pay(1, 0, amount)
        .err()
        .expect("gross limit accepted");
    assert!(format!("{error:#}").contains("gross payment"));
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
    operator.complete_close(1).unwrap();
}

#[test]
fn close_rows_allow_virtual_recipients_beyond_the_genesis_allocation_bound() {
    assert!(crate::protocol::limits().max_rows() > crate::protocol::MAX_GENESIS_ACCOUNTS as u64);
}

#[test]
fn genesis_allocations_allow_shared_display_labels() {
    let database = TempDatabase::new();
    let identities = [101, 102]
        .into_iter()
        .map(|seed| AccountIdentity {
            name: "Account",
            key: Wallet::from_seed("Account", seed).public_key(),
        })
        .collect::<Vec<_>>();
    let configured = identities
        .iter()
        .map(|identity| Account {
            key: identity.key.clone(),
            balance: 7,
        })
        .collect::<Vec<_>>();
    for _ in 0..2 {
        let store = Store::open_configured(database.path(), &identities, &configured).unwrap();
        let operator = Operator::from_store(
            store,
            identities.clone(),
            Protocol::new(NonZeroUsize::MIN).unwrap(),
            None,
            &configured,
            None,
            4096,
        )
        .unwrap();
        assert_eq!(operator.store.current_liability().unwrap(), 14);
        for identity in &identities {
            let head = operator.payment_head(&identity.key).unwrap();
            assert_eq!(head.opening.account, identity.key);
            assert_eq!(head.balance, 7);
        }
    }
}

struct PendingAdmission {
    records: BTreeMap<u64, AdmittedRootsResponse>,
}

struct AmbiguousAdmission {
    client: client::Client,
    visible: Arc<std::sync::atomic::AtomicBool>,
    reads: Arc<AtomicU64>,
    submissions: Arc<AtomicU64>,
}

impl ChainBackend for AmbiguousAdmission {
    fn deployment(&self) -> Digest {
        deployment()
    }

    async fn read<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        if matches!(request.lookup, Lookup::Admitted { .. }) {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if !self.visible.load(Ordering::SeqCst) {
                anyhow::bail!("admission effect read unavailable");
            }
        }
        self.client.read(ctx, request).await
    }

    async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        self.read(ctx, request).await
    }

    async fn submit<E: Env>(&mut self, ctx: &E, tx: &SettlementTx) -> Result<Submission> {
        assert!(matches!(tx, SettlementTx::Admit(_)));
        if self.submissions.fetch_add(1, Ordering::SeqCst) == 0 {
            self.client.submit(ctx, tx).await?;
        }
        anyhow::bail!("submission response lost");
    }
}

#[test]
fn uncertain_admission_reuses_the_durable_close_until_its_effect_is_visible() {
    for stop_pipeline in [false, true] {
        deterministic::Runner::default().start(|context| async move {
            let chain = Chain::new(&context).await;
            let database = TempDatabase::new();
            let saved;
            {
                let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
                chain.register(&mut operator).await;
                operator.pay(0, 1, 5).unwrap();
                let prepared = operator
                    .balances
                    .prepare(
                        operator.store.load_current().unwrap(),
                        operator.registration.clone(),
                    )
                    .unwrap();
                rotate_epoch(&mut operator, 0);
                saved = operator.balances.complete(prepared, 0).unwrap().encode();
            }
            let visible = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reads = Arc::new(AtomicU64::new(0));
            let submissions = Arc::new(AtomicU64::new(0));
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (certifier, mailbox) = node::Certifier::new(
                context.child("uncertain_admission"),
                node::Config {
                    verifier: protocol.verifier(),
                    chain: AmbiguousAdmission {
                        client: client::Client::new(
                            chain.control.identity(),
                            deployment(),
                            vec![SocketAddr::from(([127, 0, 0, 1], 9_800))],
                            context.child("client_rng"),
                        )
                        .unwrap(),
                        visible: Arc::clone(&visible),
                        reads: Arc::clone(&reads),
                        submissions: Arc::clone(&submissions),
                    },
                    mailbox_size: NonZeroUsize::new(10).unwrap(),
                },
            );
            let peers = (0..crate::protocol::committee().unwrap().members().len())
                .map(|index| ed25519::PrivateKey::from_seed(index as u64).public_key())
                .collect::<Vec<_>>();
            let mut task = Some(certifier.start(inert_channel(peers.clone())));
            let pipeline = node::Pipeline::new(mailbox, &peers, deployment()).unwrap();
            let identities = identities();
            let store = Store::open(database.path(), &identities).unwrap();
            let mut recovered = Operator::from_store(
                store,
                identities,
                protocol,
                Some(pipeline),
                &accounts(),
                None,
                4096,
            )
            .unwrap();
            assert_eq!(recovered.balances.startup_work().unwrap(), (vec![], vec![]));
            let mut released_after_retry = false;
            for _ in 0..40_000 {
                if let Err(error) = recovered.advance_close() {
                    assert!(
                        stop_pipeline && error.downcast_ref::<node::PipelineStopped>().is_some(),
                        "{error:#}"
                    );
                    break;
                }
                assert!(
                    !matches!(
                        recovered.store.close_outcome(0).unwrap(),
                        StoredCloseOutcome::Failed(_)
                    ),
                    "availability loss permanently failed a certified close"
                );
                if !released_after_retry
                    && reads.load(Ordering::SeqCst) > client::SUBMIT_ATTEMPTS as u64
                {
                    assert_eq!(
                        recovered
                            .balances
                            .stored_result(0)
                            .unwrap()
                            .unwrap()
                            .encode(),
                        saved
                    );
                    released_after_retry = true;
                    if stop_pipeline {
                        let task = task.take().unwrap();
                        task.abort();
                        let _ = task.await;
                    } else {
                        visible.store(true, Ordering::SeqCst);
                    }
                }
                if recovered.active_close.is_none() {
                    break;
                }
                std::thread::yield_now();
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(released_after_retry);
            assert!(recovered.active_close.is_none());
            if stop_pipeline {
                assert!(matches!(
                    recovered.store.close_outcome(0).unwrap(),
                    StoredCloseOutcome::Pending
                ));
                for _ in 0..10 {
                    recovered.advance_close().unwrap();
                    assert!(recovered.active_close.is_none());
                }
                drop(recovered);
                let Some(Record::Admitted(admitted)) =
                    chain.control.record(admitted_key(&deployment(), 0)).await
                else {
                    panic!("the first submission executed on the native chain");
                };
                recovered =
                    reopen_admitted(&context, database.path(), [(0, admitted)].into()).await;
            }
            assert_eq!(recovered.admitted.len(), 1);
            assert_eq!(
                recovered
                    .balances
                    .stored_result(0)
                    .unwrap()
                    .unwrap()
                    .encode(),
                saved
            );
            assert_eq!(recovered.balances.startup_work().unwrap(), (vec![], vec![]));
            assert!(matches!(
                chain.control.record(admitted_key(&deployment(), 0)).await,
                Some(Record::Admitted(_))
            ));
            if let Some(task) = task {
                task.abort();
                let _ = task.await;
            }
        });
    }
}

fn admit_pending(operator: &mut Operator) -> AdmittedRootsResponse {
    let epoch = operator.registration.context.payment().epoch();
    let prepared = operator
        .balances
        .prepare(
            operator.store.load_current().unwrap(),
            operator.registration.clone(),
        )
        .unwrap();
    rotate_epoch(operator, epoch);
    let result = operator.balances.complete(prepared, epoch).unwrap();
    let record = AdmittedRootsResponse {
        batch_id: result.header.batch_id::<Sha256>(),
        roots: result.roots,
        finalized: false,
    };
    operator.record_admission(result).unwrap();
    record
}

#[test]
fn confirmed_deposit_staging_does_not_wait_for_close_recovery() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 0);
    }
    let mut recovered = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(recovered.fault().is_some());
    let event = DepositEvent {
        id: Sha256::hash(&[b"recovery-deposit"]),
        account: recovered.wallets[0].public_key(),
        amount: 7,
    };
    let staged = recovered.observe(std::slice::from_ref(&event)).unwrap();
    assert_eq!(staged.len(), 1);
    assert!(recovered.pay(0, 1, 1).is_err());
    recovered.wait_for_closes().unwrap();
    assert!(recovered.observe(&[event]).unwrap().is_empty());
    assert_eq!(
        recovered
            .payment_head(&recovered.wallets[0].public_key())
            .unwrap()
            .balance,
        102
    );
}

async fn reopen_admitted(
    context: &deterministic::Context,
    path: &Path,
    records: BTreeMap<u64, AdmittedRootsResponse>,
) -> Operator {
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let (certifier, mailbox) = node::Certifier::new(
        context.child("recovery_certifier"),
        node::Config {
            verifier: protocol.verifier(),
            chain: PendingAdmission { records },
            mailbox_size: NonZeroUsize::new(10).unwrap(),
        },
    );
    let peers = (0..crate::protocol::committee().unwrap().members().len())
        .map(|index| ed25519::PrivateKey::from_seed(index as u64).public_key())
        .collect::<Vec<_>>();
    certifier.start(inert_channel(peers.clone()));
    let pipeline = node::Pipeline::new(mailbox, &peers, deployment()).unwrap();
    let identities = identities();
    let store = Store::open(path, &identities).unwrap();
    let mut recovered = Operator::from_store(
        store,
        identities,
        protocol,
        Some(pipeline),
        &accounts(),
        None,
        4096,
    )
    .unwrap();
    assert_eq!(recovered.balances.startup_work().unwrap(), (vec![], vec![]));
    while recovered.active_close.is_some() {
        recovered.advance_close().unwrap();
        std::thread::yield_now();
        context.sleep(Duration::from_millis(1)).await;
    }
    recovered
}

#[test]
fn admitted_ancestors_recover_before_finality_without_recertification() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        operator.pay(0, operator.wallet_count(), 5).unwrap();
        let mut first = admit_pending(&mut operator);
        operator.pay(1, 2, 7).unwrap();
        let mut second = admit_pending(&mut operator);
        assert_eq!(operator.pending_epochs().unwrap(), [0, 1]);
        assert!(operator.store.latest_finalized_root().unwrap().is_none());
        assert_eq!(
            operator.payment_head(&eve_identity().key).unwrap().balance,
            5
        );
        drop(operator);

        let mut recovered =
            reopen_admitted(&context, database.path(), [(0, first), (1, second)].into()).await;

        assert!(recovered.fault().is_none());
        assert_eq!(recovered.admitted.len(), 2);
        assert!(recovered.store.latest_finalized_root().unwrap().is_none());
        assert_eq!(
            recovered.payment_head(&eve_identity().key).unwrap().balance,
            5
        );
        assert_eq!(recovered.pay(2, 3, 1).unwrap().epoch, 2);

        second.finalized = true;
        recovered.observe_admitted(1, &second).unwrap();
        assert!(recovered.store.latest_finalized_root().unwrap().is_none());
        first.finalized = true;
        recovered.observe_admitted(0, &first).unwrap();
        assert_eq!(
            recovered.payment_head(&eve_identity().key).unwrap().balance,
            5
        );
        recovered.observe_admitted(1, &second).unwrap();
        assert_eq!(
            recovered.store.latest_finalized_root().unwrap(),
            Some((1, second.roots.successor))
        );
        assert!(recovered.pending_epochs().unwrap().is_empty());
        assert!(recovered.balances.stored_result(0).unwrap().is_some());
    });
}

#[test]
fn invalidated_suffix_preserves_pending_clean_prefix_across_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        operator.pay(0, 1, 5).unwrap();
        let mut first = admit_pending(&mut operator);
        operator.pay(1, 2, 5).unwrap();
        admit_pending(&mut operator);
        operator
            .fence_suffix(1, "certified challenge of epoch 1".to_string())
            .unwrap();
        assert_eq!(operator.pending_epochs().unwrap(), [0]);
        assert!(operator.pay(2, 3, 1).is_err());
        drop(operator);

        let mut recovered = reopen_admitted(&context, database.path(), [(0, first)].into()).await;

        assert_eq!(recovered.admitted.len(), 1);
        first.finalized = true;
        recovered.observe_admitted(0, &first).unwrap();
        assert_eq!(
            recovered.store.latest_finalized_root().unwrap(),
            Some((0, first.roots.successor))
        );
        assert!(matches!(
            recovered.store.close_outcome(1).unwrap(),
            StoredCloseOutcome::Failed(_)
        ));
        assert!(recovered.pay(2, 3, 1).is_err());
    });
}

#[test]
fn active_successor_cannot_finalize_after_ancestor_challenge() {
    let mut operator = operator();
    operator.pay(0, 1, 5).unwrap();
    admit_pending(&mut operator);
    operator.pay(1, 2, 5).unwrap();
    let (started, release) = operator.pause_next_close();
    operator.start_close(1).unwrap();
    started.recv().unwrap();
    operator
        .fence_suffix(0, "certified challenge of epoch 0".to_string())
        .unwrap();
    release.send(()).unwrap();
    assert!(operator.wait_for_closes().is_err());
    assert!(operator.store.latest_finalized_root().unwrap().is_none());
    assert!(operator.admitted.is_empty());
    assert!(operator.pending_epochs().unwrap().is_empty());
    for epoch in [0, 1] {
        assert!(matches!(
            operator.store.close_outcome(epoch).unwrap(),
            StoredCloseOutcome::Failed(_)
        ));
    }
}

#[test]
fn service_observer_follows_terminal_invalidation_boundary() {
    for timeout_first in [true, false] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let timing = if timeout_first {
                Timing {
                    admission_offset: 10,
                    challenge_duration: 20,
                }
            } else {
                Timing::DEFAULT
            };
            let chain = Chain {
                control: harness::start_with_native(
                    &context,
                    SocketAddr::from(([127, 0, 0, 1], 9_800)),
                    "chain",
                    harness::native(crate::protocol::deployments()),
                    timing,
                )
                .await,
            };
            let mut client = client::Client::new(
                chain.control.identity(),
                deployment(),
                vec![SocketAddr::from(([127, 0, 0, 1], 9_800))],
                TestRng::new(42),
            )
            .unwrap();
            let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
            let mut closes = Vec::new();
            for epoch in 0..3 {
                chain.register(&mut operator).await;
                operator.pay(1, 2, 1).unwrap();
                admit_pending(&mut operator);
                let close = operator.balances.stored_result(epoch).unwrap().unwrap();
                chain
                    .control
                    .submit(SettlementTx::Admit(AdmitRequest::from(&close)))
                    .await;
                assert_eq!(
                    client
                        .admitted(&context, epoch)
                        .await
                        .unwrap()
                        .unwrap()
                        .batch_id,
                    close.header.batch_id::<Sha256>()
                );
                closes.push(close);
            }
            if timeout_first {
                chain.register(&mut operator).await;
                let deadline = client
                    .registration(&context)
                    .await
                    .unwrap()
                    .unwrap()
                    .admission_deadline;
                let height = chain.control.advance(0).await;
                chain.control.advance(deadline - height + 1).await;
                assert!(matches!(
                    client.fault(&context).await.unwrap(),
                    Some(crate::chain::state::FaultRecord::Faulted(
                        crate::chain::state::HardFaultReasonResponse::ExpiredRegistration { .. }
                    ))
                ));
            }
            let operator = commonware_utils::sync::Mutex::new(operator);
            for epoch in if timeout_first { vec![2] } else { vec![2, 0] } {
                let close = &closes[epoch];
                let evidence = {
                    let operator = operator.lock();
                    let wallet = &operator.wallets[0];
                    let ack = |debit| {
                        Ack::sign_by_authorities(
                            VectorSendBody::new(
                                close.context.payment(),
                                wallet.public_key(),
                                1,
                                debit,
                                VectorRoot {
                                    digest: Sha256::hash(&[b"observer-fork"]),
                                },
                            ),
                            wallet.signer(),
                            operator.protocol.operator(),
                        )
                    };
                    commonware_clearing::bajillion::challenge::Challenge::AckFork {
                        left: Box::new(
                            commonware_clearing::bajillion::challenge::AckWitness::from_ack(&ack(
                                1,
                            )),
                        ),
                        right: Box::new(
                            commonware_clearing::bajillion::challenge::AckWitness::from_ack(&ack(
                                2,
                            )),
                        ),
                    }
                };
                chain
                    .control
                    .submit(SettlementTx::Challenge(
                        crate::chain::tx::ChallengeRequest {
                            deployment: deployment(),
                            batch_id: close.header.batch_id::<Sha256>(),
                            evidence: evidence.encode(),
                        },
                    ))
                    .await;
                crate::service::observe_closes(&context, &mut client, &operator)
                    .await
                    .unwrap();
            }
            if timeout_first {
                let height = chain.control.advance(0).await;
                chain
                    .control
                    .advance(
                        closes[1]
                            .context
                            .epoch_context()
                            .challenge_deadline()
                            .saturating_sub(height)
                            + 1,
                    )
                    .await;
            }
            chain
                .control
                .submit(SettlementTx::BeginHardFaultSettlement(
                    crate::chain::tx::BeginHardFaultSettlementRequest {
                        deployment: deployment(),
                    },
                ))
                .await;
            let Some(crate::chain::state::FaultRecord::Settling(settlement)) =
                client.fault(&context).await.unwrap()
            else {
                panic!("the actual fault sequence must reach terminal settlement");
            };
            let invalid_epoch = if timeout_first { 2 } else { 0 };
            assert_eq!(
                settlement.invalid_from,
                Some(closes[invalid_epoch].header.batch_id::<Sha256>())
            );
            assert!(match settlement.reason {
                crate::chain::state::HardFaultReasonResponse::ExpiredRegistration { .. } =>
                    timeout_first,
                crate::chain::state::HardFaultReasonResponse::ProvenChallenge {
                    batch_id, ..
                } => !timeout_first && batch_id == closes[2].header.batch_id::<Sha256>(),
                _ => false,
            });
            for _ in 0..2 {
                crate::service::observe_closes(&context, &mut client, &operator)
                    .await
                    .unwrap();
            }
            let assert_outcomes = |operator: &mut Operator| {
                assert!(operator.pending_epochs().unwrap().is_empty());
                assert!(!operator.close_in_progress());
                for epoch in 0..3 {
                    if epoch < invalid_epoch {
                        assert!(matches!(
                            operator.poll_close(epoch as u64).unwrap(),
                            Some(CloseEvent::Finished(_))
                        ));
                    } else {
                        assert!(matches!(
                            operator.poll_close(epoch as u64).unwrap(),
                            Some(CloseEvent::Failed { .. })
                        ));
                    }
                }
            };
            assert_outcomes(&mut operator.lock());
            drop(operator);
            let operator = commonware_utils::sync::Mutex::new(
                Operator::open(database.path(), NonZeroUsize::MIN).unwrap(),
            );
            crate::service::observe_closes(&context, &mut client, &operator)
                .await
                .unwrap();
            assert_outcomes(&mut operator.lock());
        });
    }
}

#[test]
fn active_successor_storage_failure_remains_fatal_after_ancestor_fault() {
    let mut operator = operator();
    operator.pay(0, 1, 5).unwrap();
    admit_pending(&mut operator);
    operator.pay(1, 2, 5).unwrap();
    operator.balances.fail_after_journal().unwrap();
    let (started, release) = operator.pause_next_close();
    operator.start_close(1).unwrap();
    started.recv().unwrap();
    operator
        .fence_suffix(0, "certified ancestor challenge".into())
        .unwrap();
    release.send(()).unwrap();
    assert!(operator.wait_for_closes().is_err());
    assert!(
        operator.ensure_store_usable().is_err(),
        "a durable fault must not hide a failed balance owner"
    );
}

fn adopt_at(operator: &mut Operator, registered: u64, timing: Timing) {
    let current = &operator.registration;
    let replacement = operator
        .protocol
        .registration_at(
            current.context.payment().epoch(),
            current.deposits.clone(),
            current.withdrawals.clone(),
            current.context.predecessor_liability(),
            registered + timing.admission_offset,
            registered + timing.admission_offset + timing.challenge_duration,
        )
        .unwrap();
    operator
        .adopt_registration(&RegistrationRecord {
            epoch: replacement.context.payment().epoch(),
            predecessor_liability: replacement.context.predecessor_liability(),
            anchor: *replacement.context.payment().anchor(),
            admission_deadline: replacement.context.admission_deadline(),
            challenge_deadline: replacement.context.challenge_deadline(),
            deposits_root: replacement.deposits.root::<Sha256>().unwrap(),

            withdrawals_root: replacement.withdrawals.root::<Sha256>().unwrap(),
            admitted: None,
        })
        .unwrap();
}

#[test]
fn automatic_cut_obeys_certified_dwell_runway_and_epoch_token() {
    deterministic::Runner::default().start(|_| async move {
        for offset in [1, 4, 10, 30] {
            let mut operator = operator();
            let timing = Timing {
                admission_offset: offset,
                challenge_duration: 8,
            };
            assert!(operator.automatic_epoch().unwrap().is_none());
            adopt_at(&mut operator, 10, timing);
            assert_eq!(operator.automatic_epoch().unwrap(), Some(0));
            operator.pay(0, 1, 1).unwrap();
            let due = (10 + 4).min(10 + offset - offset.min(4));
            assert!(operator.close_if_due(0, due - 1, timing).unwrap().is_none());
            assert_eq!(
                operator
                    .close_if_due(0, due, timing)
                    .unwrap()
                    .unwrap()
                    .epoch,
                0
            );
            operator.pay(1, 2, 1).unwrap();
            assert!(
                operator
                    .close_if_due(0, due + 100, timing)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(operator.status().unwrap().epoch, 1);
            operator.wait_for_closes().unwrap();
        }
    });
}

#[test]
fn automatic_cut_releases_capacity_and_respects_pending_bound() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator();
        for _ in 0..MAX_DEPOSIT_EVENTS {
            operator.deposit(0, 1).unwrap();
        }
        let timing = Timing {
            admission_offset: 30,
            challenge_duration: 8,
        };
        adopt_at(&mut operator, 10, timing);
        assert!(operator.close_if_due(0, 10, timing).unwrap().is_some());
        operator.wait_for_closes().unwrap();
        for _ in 0..MAX_PENDING_CLOSES {
            operator.pay(0, 1, 1).unwrap();
            admit_pending(&mut operator);
        }
        operator.pay(0, 1, 1).unwrap();
        assert!(operator.automatic_epoch().unwrap().is_none());
        assert_eq!(operator.pending_epochs().unwrap().len(), MAX_PENDING_CLOSES);
        assert!(operator.signed_registration().is_err());
    });
}

impl ChainBackend for PendingAdmission {
    fn deployment(&self) -> Digest {
        deployment()
    }

    async fn read<E: Env>(&mut self, _: &E, request: &ReadRequest) -> Result<Verified> {
        let record = match request.lookup {
            Lookup::Admitted { epoch } => self.records.get(&epoch).copied().map(Record::Admitted),
            Lookup::Fault => None,
            _ => anyhow::bail!("unexpected admission lookup"),
        };
        Ok(Verified {
            height: 1,
            timestamp: 0,
            record,
        })
    }

    async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        self.read(ctx, request).await
    }

    async fn submit<E: Env>(&mut self, _: &E, tx: &SettlementTx) -> Result<Submission> {
        assert!(
            matches!(tx, SettlementTx::Admit(request) if self.records.contains_key(&request.epoch))
        );
        Ok(Submission::Accepted)
    }
}

#[test]
fn certified_admission_completes_before_clearing_finality() {
    deterministic::Runner::default().start(|context| async move {
        let mut operator = operator();
        operator.pay(0, 1, DEFAULT_AMOUNT).unwrap();
        let result = operator.complete_close(0).unwrap();
        let mut chain = PendingAdmission {
            records: [(result.context.payment().epoch(), AdmittedRootsResponse::new(result.header.batch_id::<Sha256>(), result.roots, false))].into(),
        };
        commonware_macros::select! {
            outcome = client::admit(&context, &mut chain, AdmitRequest::from(&result)) => outcome.unwrap(),
            _ = context.sleep(Duration::from_secs(1)) => panic!("certified admission waited for clearing finalization"),
        }
        assert!(!chain.records[&result.context.payment().epoch()].finalized);
    });
}

/// Unwraps one claim resolution: the release record proving exactly this
/// claim consumed its position.
fn released<T: std::fmt::Debug>(outcome: Option<T>) -> T {
    outcome.expect("the claim released nothing")
}

/// The settlement chain these tests co-simulate with the operator: a harness
/// chain driven at the transaction level, with every verdict read from
/// executed state.
struct Chain {
    control: harness::Control,
}

impl Chain {
    async fn new(context: &deterministic::Context) -> Self {
        let control =
            harness::start(context, SocketAddr::from(([127, 0, 0, 1], 9_800)), "chain").await;
        Self { control }
    }

    async fn deposit(&self, event: DepositEvent) {
        let wallet = wallets()
            .into_iter()
            .find(|wallet| wallet.public_key() == event.account)
            .unwrap_or_else(|| crate::protocol::Wallet::from_seed("stranger", 999));
        assert_eq!(wallet.public_key(), event.account);
        let native = harness::native(crate::protocol::deployments());
        self.control
            .submit(SettlementTx::Deposit(
                crate::chain::tx::DepositRequest::sign(
                    native.chain_id(),
                    deployment(),
                    event.clone(),
                    wallet.signer(),
                ),
            ))
            .await;
        assert!(matches!(
            self.control.record(deposit_key(&deployment(), &event.id)).await,
            Some(Record::Deposit(recorded)) if recorded == event
        ));
    }

    async fn queue_withdrawal(
        &self,
        request: SignedWithdrawal<Key, Digest>,
        openings: Vec<StateOpening<Key, Digest>>,
    ) {
        let account = request.account().clone();
        self.control
            .submit(SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: request.clone(),
                openings,
            }))
            .await;
        assert!(matches!(
            self.control.record(withdrawal_key(&deployment(), &account)).await,
            Some(Record::Withdrawal(recorded)) if recorded == request
        ));
    }

    /// Submits the operator's boundary-only signed registration, returning
    /// the registration record it landed, or `None` when the registration
    /// left no effect.
    async fn try_register(&self, operator: &mut Operator) -> Option<RegistrationRecord> {
        let register = operator.signed_registration().unwrap();
        let epoch = register.epoch;
        self.control
            .submit(SettlementTx::RegisterEpoch(register))
            .await;
        match self.control.record(registration_key(&deployment())).await {
            Some(Record::Registration(record)) if record.epoch == epoch => Some(record),
            _ => None,
        }
    }

    /// Registers the operator's live epoch and adopts the chain-assigned
    /// deadlines and anchor from the certified registration record.
    async fn register(&self, operator: &mut Operator) {
        let record = self
            .try_register(operator)
            .await
            .expect("the registration earned no record");
        operator.adopt_registration(&record).unwrap();
    }

    /// Admits the close and verifies its certified finalization.
    async fn admit(&self, result: &SettlementResult) {
        self.control
            .submit(SettlementTx::Admit(AdmitRequest::from(result)))
            .await;
        let deadline = result.context.epoch_context().challenge_deadline();
        let height = self.control.advance(0).await;
        if height <= deadline {
            self.control.advance(deadline - height + 1).await;
        }
        match self
            .control
            .record(admitted_key(
                &deployment(),
                result.context.payment().epoch(),
            ))
            .await
        {
            Some(Record::Admitted(admitted)) => {
                assert_eq!(admitted.batch_id, result.header.batch_id::<Sha256>());
                assert_eq!(admitted.roots.change, result.roots.change);
                assert!(admitted.finalized);
            }
            record => panic!("expected an admitted record, found {record:?}"),
        }
        let status = self.status().await;
        assert!(
            status
                .last_finalized
                .is_some_and(|last| last >= result.context.payment().epoch())
        );
        if status.last_finalized == Some(result.context.payment().epoch()) {
            assert_eq!(status.state_root, result.roots.successor);
        }
    }

    async fn status(&self) -> StatusRecord {
        match self.control.record(status_key(&deployment())).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected the status record, found {record:?}"),
        }
    }

    /// Submits one withdrawal claim and resolves it by its effect record:
    /// `Some` when the release record proves exactly this claim consumed the
    /// position, `None` when these bytes released nothing (an unavailable
    /// batch, an adjudicated rejection, or a position consumed by other
    /// bytes are all effect-free for them).
    async fn claim_withdrawal(
        &self,
        batch_id: BatchId<Digest>,
        claim: &WithdrawalClaim<Digest>,
    ) -> Option<WithdrawalResponse> {
        let tx = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            batch_id,
            claim: claim.clone(),
        });
        self.control.submit(tx).await;
        match self
            .control
            .record(withdrawal_release_key(
                &deployment(),
                &batch_id,
                claim.position(),
            ))
            .await
        {
            Some(Record::WithdrawalRelease(release))
                if release.claim == Sha256::hash(&[&claim.encode()]) =>
            {
                Some(release.released)
            }
            _ => None,
        }
    }
}

fn amount(value: u64) -> WithdrawalAction {
    WithdrawalAction::Amount(NonZeroU64::new(value).unwrap())
}

fn start_current_close(operator: &mut Operator) -> Result<CloseStarted> {
    let epoch = operator.registration.context.payment().epoch();
    operator.start_close(epoch)
}

fn rotate_epoch(operator: &mut Operator, epoch: u64) {
    let successor = operator
        .protocol
        .registration(
            epoch.checked_add(1).unwrap(),
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.successor_liability().unwrap(),
        )
        .unwrap();
    operator
        .store
        .rotate_epoch(
            epoch,
            operator.registration.context.payment(),
            &successor.context,
        )
        .unwrap();
    operator.registration = successor;
    operator.validate_current_epoch().unwrap();
}

#[test]
fn payment_is_atomic_and_rejects_overspend() {
    let mut operator = operator();
    let accepted = operator.pay(0, 1, 25).unwrap();
    assert_eq!(accepted.epoch, 0);
    assert!(operator.pay(0, 1, 76).is_err());
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        75
    );
}

#[test]
fn accepted_batch_reads_across_the_operating_fence() {
    let mut operator = operator();
    let (send, entries) = operator
        .sign_send(0, &[(operator.wallets[1].public_key(), 25)])
        .unwrap();
    let committed = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();

    // Sign a second send that is never accepted, before any fence blocks quoting.
    let (uncommitted, uncommitted_entries) = operator
        .sign_send(3, &[(operator.wallets[2].public_key(), 1)])
        .unwrap();

    // A close fence blocks admitting new state but leaves the committed rows readable.
    operator.close_fault = Some("fenced after a failed predecessor close".to_string());
    assert!(operator.accept_send(send.clone(), entries.clone()).is_err());
    let resolved = operator
        .accepted_batch(&send, &entries)
        .unwrap()
        .expect("a fenced operator failed to read a committed batch");
    assert_eq!(resolved.acceptance, committed.acceptance);
    assert!(
        operator
            .accepted_batch(&uncommitted, &uncommitted_entries)
            .unwrap()
            .is_none()
    );

    // A storage fault is fatal to the instance until it restarts, so the read refuses
    // to answer instead of reporting a false absence.
    operator.store_fault = Some("the SQLite connection is unusable".to_string());
    assert!(operator.accepted_batch(&send, &entries).is_err());
    assert!(
        operator
            .accepted_batch(&uncommitted, &uncommitted_entries)
            .is_err()
    );
}

#[test]
fn arbitrary_absent_receiver_is_credited_and_persisted_at_close() {
    let mut operator = operator();
    let receiver = Wallet::from_seed("Mallory", 9_999).public_key();
    let (send, entries) = operator.sign_send(0, &[(receiver.clone(), 25)]).unwrap();

    operator.accept_send(send, entries).unwrap();
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        INITIAL_BALANCE - 25
    );
    assert_eq!(
        operator
            .store
            .current_account(&receiver)
            .unwrap()
            .unwrap()
            .current,
        25
    );
    assert!(operator.payment_head(&receiver).is_err());
    let result = operator.complete_close(28).unwrap();
    let head = operator.payment_head(&receiver).unwrap();
    assert_eq!(head.balance, 25);
    assert_eq!(
        head.opening
            .verify::<Sha256>(&result.roots.successor)
            .unwrap()
            .get(),
        25
    );
    assert_eq!(operator.store.current_liability().unwrap(), 400);
}

#[test]
fn compact_status_does_not_materialize_epoch_artifacts() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    operator.pay(0, 1, 1).unwrap();
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute("UPDATE accepted_entries SET opening = zeroblob(256)", [])
        .unwrap();

    let status = operator.status().unwrap();
    assert_eq!(status.accounts, 4);
    assert_eq!(status.present_accounts, 4);
    assert_eq!(status.recent_payments, 1);
}

#[test]
fn payment_head_serves_the_retained_predecessor_root() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let payer = operator.wallets[0].public_key();
    let before = operator.payment_head(&payer).unwrap();
    for amount in [3, 4, 5] {
        operator.pay(0, 1, amount).unwrap();
    }

    // The predecessor commitment is constant across the epoch. Only the live account
    // state moves with accepted payments.
    let after = operator.payment_head(&payer).unwrap();
    assert_eq!(after.root, before.root);
    assert_eq!(after.opening, before.opening);
    assert_eq!(after.balance, before.balance - 12);
    assert_eq!(
        operator
            .store
            .payer_endpoint(&payer)
            .unwrap()
            .cumulative_debit,
        12
    );

    // Head reads open QMDB and never replay the acknowledgment log:
    // tampering with a stored row is invisible here. Startup replays and verifies every
    // row, so the reopened operator must reject the same database loudly.
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    let mut tampered: Vec<u8> = connection
        .query_row("SELECT ack FROM acks WHERE seq = 1", [], |row| row.get(0))
        .unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE acks SET ack = ?1 WHERE seq = 1",
            [tampered.as_slice()],
        )
        .unwrap();
    let reread = operator.payment_head(&payer).unwrap();
    assert_eq!(reread.root, after.root);
    assert_eq!(reread.balance, after.balance);
    assert_eq!(reread.opening, after.opening);
    drop(operator);
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("tampered acknowledgment log reopened cleanly"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("verify stored acknowledgment"));
}

#[test]
fn current_balance_restart_does_not_prepare_or_apply_history() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    operator.pay(0, 1, 7).unwrap();
    operator.complete_close(21).unwrap();
    let root = operator.balances.root(1).unwrap();
    drop(operator);

    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(operator.balances.startup_work().unwrap(), (vec![], vec![]));
    assert_eq!(operator.balances.root(1).unwrap(), root);
}

#[test]
fn historical_balance_reads_preserve_the_current_close_owner() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let payer = operator.wallets[0].public_key();
    let genesis = operator.balances.root(0).unwrap();
    operator.pay(0, 1, 7).unwrap();
    operator.complete_close(19).unwrap();
    let successor = operator.balances.root(1).unwrap();
    drop(operator);

    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    for (epoch, root, balance) in [
        (0, genesis, INITIAL_BALANCE),
        (1, successor, INITIAL_BALANCE - 7),
    ] {
        let opening = operator.balances.opening(epoch, &payer).unwrap();
        assert_eq!(opening.verify::<Sha256>(&root).unwrap().get(), balance);
        assert!(
            operator
                .balances
                .opening(epoch, &eve_identity().key)
                .is_err()
        );
    }
    assert!(operator.balances.opening(2, &payer).is_err());
    assert_eq!(operator.balances.root(1).unwrap(), successor);
    operator.pay(0, 1, 3).unwrap();
    operator.complete_close(20).unwrap();
    let expected = operator.balances.root(2).unwrap();
    drop(operator);

    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(operator.balances.root(2).unwrap(), expected);
    assert_eq!(
        operator.payment_head(&payer).unwrap().balance,
        INITIAL_BALANCE - 10
    );
    let opening = operator.balances.opening(0, &payer).unwrap();
    assert_eq!(
        opening.verify::<Sha256>(&genesis).unwrap().get(),
        INITIAL_BALANCE
    );
}

#[test]
fn journaled_qmdb_close_replays_after_crash_before_apply() {
    for after_journal in [false, true] {
        let database = TempDatabase::new();
        let expected;
        {
            let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
            operator.pay(0, 1, 7).unwrap();
            let prepared = operator
                .balances
                .prepare(
                    operator.store.load_current().unwrap(),
                    operator.registration.clone(),
                )
                .unwrap();
            expected = prepared.close().roots.successor;
            drop(prepared);
            if after_journal {
                operator.balances.fail_after_journal().unwrap();
            } else {
                operator.balances.fail_read().unwrap();
            }
            start_current_close(&mut operator).unwrap();
            let error = match operator.wait_for_closes() {
                Ok(_) => panic!("injected crash completed"),
                Err(error) => error,
            };
            assert!(format!("{error:#}").contains("injected"));
            assert!(operator.store.failed_close().unwrap().is_none());
            assert_eq!(operator.store.closing_epoch_from(0).unwrap(), Some(0));
        }
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        let expected_replay = if after_journal { vec![1] } else { vec![] };
        assert_eq!(
            operator.balances.startup_work().unwrap(),
            (expected_replay.clone(), expected_replay)
        );
        let closes = operator.wait_for_closes().unwrap();
        assert!(matches!(closes.as_slice(), [CloseEvent::Finished(close)] if close.epoch == 0));
        assert_eq!(operator.balances.root(1).unwrap(), expected);
        let payer = operator.wallets[0].public_key();
        assert_eq!(
            operator.payment_head(&payer).unwrap().balance,
            INITIAL_BALANCE - 7
        );
        operator.pay(0, 1, 3).unwrap();
        operator.complete_close(18).unwrap();
        assert_eq!(
            operator.payment_head(&payer).unwrap().balance,
            INITIAL_BALANCE - 10
        );
        drop(operator);
        let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        let evidence = operator
            .committed_entry(&payer, &operator.wallets[1].public_key(), 0)
            .unwrap();
        assert_eq!(
            evidence
                .lookup
                .resolve::<Sha256>(
                    &evidence.change_root,
                    &payer,
                    &operator.wallets[1].public_key()
                )
                .unwrap(),
            (7, 1)
        );
    }
}

#[test]
fn balance_database_has_one_live_owner() {
    let database = TempDatabase::new();
    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(Operator::open(database.path(), NonZeroUsize::MIN).is_err());
    drop(operator);
    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(operator.fault().is_none());
}

#[test]
fn unapplied_successor_root_is_unavailable_while_sql_payments_continue() {
    let mut operator = operator();
    operator.pay(0, 1, 7).unwrap();
    let (started, release) = operator.pause_next_close();
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let payer = operator.wallets[0].public_key();
    assert!(operator.payment_head(&payer).is_err());
    assert_eq!(operator.pay(0, 1, 3).unwrap().epoch, 1);
    release.send(()).unwrap();
    operator.wait_for_closes().unwrap();
    let head = operator.payment_head(&payer).unwrap();
    assert_eq!(head.balance, INITIAL_BALANCE - 10);
    assert_eq!(
        head.opening.verify::<Sha256>(&head.root).unwrap().get(),
        INITIAL_BALANCE - 7
    );
}

#[test]
fn payment_retry_returns_the_original_receipt_without_a_second_debit() {
    let mut operator = operator();
    let receiver = operator.wallets[1].public_key();
    let (send, entries) = operator.sign_send(0, &[(receiver, 25)]).unwrap();

    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    let retry = operator.accept_send(send, entries).unwrap().into_accepted();
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);

    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        75
    );
}

#[test]
fn payment_retry_survives_epoch_cutover() {
    let mut operator = operator();
    let receiver = operator.wallets[1].public_key();
    let (send, entries) = operator.sign_send(0, &[(receiver, 25)]).unwrap();

    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    rotate_epoch(&mut operator, 0);
    assert!(
        !operator
            .send_requires_epoch_registration(&send, &entries)
            .unwrap()
    );
    let retry = operator.accept_send(send, entries).unwrap().into_accepted();

    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);
    assert_eq!(operator.snapshot().unwrap().payments.len(), 0);
}

#[test]
fn accepted_endpoints_are_scoped_to_their_immutable_epoch() {
    let mut byzantine = operator();
    let payer = byzantine.wallets[0].public_key();
    let receiver = byzantine.wallets[1].public_key();
    byzantine.pay(0, 1, 7).unwrap();
    rotate_epoch(&mut byzantine, 0);
    let endpoint = byzantine.store.payer_endpoint(&payer).unwrap();
    assert_eq!((endpoint.seq, endpoint.cumulative_debit), (0, 0));
    let next = byzantine.pay(0, 1, 7).unwrap();
    assert_eq!(next.acceptance.ack.body().cumulative_debit(), 7);
    assert_eq!(
        byzantine
            .store
            .current_account(&payer)
            .unwrap()
            .unwrap()
            .current,
        INITIAL_BALANCE - 14
    );

    // The honest roll: the old-context send was never accepted and its epoch is cut,
    // so only the retry commits. The dead bytes afterward earn the typed corrective
    // rejection carrying the live context and the committed endpoint, never a debit.
    let mut honest = operator();
    let (dead, dead_entries) = honest.sign_send(0, &[(receiver.clone(), 7)]).unwrap();

    // An unrelated payment gives the epoch content to close. The payer's send was
    // never accepted, so the cut commits nothing of it.
    honest.pay(2, 3, 5).unwrap();
    rotate_epoch(&mut honest, 0);
    let (retry, retry_entries) = honest.sign_send(0, &[(receiver.clone(), 7)]).unwrap();
    let committed = honest
        .accept_send(retry, retry_entries)
        .unwrap()
        .into_accepted();
    assert_eq!(committed.total, 7);
    match honest.accept_send(dead, dead_entries).unwrap() {
        SendOutcome::Stale {
            context,
            cumulative_debit,
            seq,
            entries,
        } => {
            assert_eq!(&context, honest.registration.context.payment());
            assert_eq!(cumulative_debit, 7);
            assert_eq!(seq, 1);
            assert_eq!(
                entries,
                vec![OutEntry {
                    recipient: receiver,
                    cumulative: 7,
                    count: 1,
                }]
            );
        }
        SendOutcome::Accepted(_) => panic!("a dead-context send was accepted"),
    }
    assert_eq!(
        honest
            .store
            .payer_endpoint(&payer)
            .unwrap()
            .cumulative_debit,
        7
    );
}

/// A re-signed different body at an already accepted sequence is wallet equivocation
/// against its own endpoint chain, so acceptance fails closed instead of correcting.
#[test]
fn conflicting_body_at_an_accepted_sequence_is_refused() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let receiver = operator.wallets[2].public_key();
    operator.pay(0, 1, 7).unwrap();

    // Sequence one is committed crediting wallet one. Re-sign it crediting wallet two
    // with the same endpoint arithmetic.
    let context = operator.registration.context.payment().clone();
    let (conflict, conflict_entries) = sign_send_at(
        &context,
        &operator.wallets[0],
        &Endpoint {
            cumulative_debit: 0,
            seq: 0,
            entries: Vec::new(),
        },
        &[(receiver, 7)],
    )
    .unwrap();
    let error = match operator.accept_send(conflict, conflict_entries) {
        Ok(_) => panic!("a conflicting body at an accepted sequence was admitted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("bound to another accepted endpoint"));
    assert_eq!(
        operator
            .store
            .payer_endpoint(&payer)
            .unwrap()
            .cumulative_debit,
        7
    );
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
}

#[test]
fn incoming_entries_serve_verifiable_receipts_in_cursor_order() {
    let mut operator = operator();
    let receiver = operator.wallets[1].public_key();
    operator.pay(0, 1, 2).unwrap();
    operator.pay(2, 1, 3).unwrap();
    let context = operator.registration.context.payment().clone();

    let first = operator.incoming_payments(&receiver, 0, 10).unwrap();
    assert_eq!(first.len(), 2);
    for incoming in &first {
        assert_eq!(incoming.receipt.recipient, receiver);
        incoming.receipt.verify::<Sha256>(&context).unwrap();
    }
    let after = operator
        .incoming_payments(&receiver, first[0].sequence, 10)
        .unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].sequence, first[1].sequence);

    // A second batch from the same payer advances the same edge cumulatively.
    operator.pay(0, 1, 5).unwrap();
    let all = operator.incoming_payments(&receiver, 0, 10).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].receipt.cumulative, 7);
    assert_eq!(all[2].receipt.count, 2);
    all[2].receipt.verify::<Sha256>(&context).unwrap();
}

#[test]
fn finalized_cache_retirement_preserves_receipts_and_live_vectors() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let payer = operator.wallets[0].public_key();
    let recipient = operator.wallets[1].public_key();
    let (authorization, entries) = operator.sign_send(0, &[(recipient.clone(), 2)]).unwrap();
    let accepted = operator
        .accept_send(authorization.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    let acceptance = accepted.acceptance.encode();
    operator.pay(0, 1, 3).unwrap();
    let receipts = operator
        .incoming_payments(&recipient, 0, 10)
        .unwrap()
        .into_iter()
        .map(|v| (v.sequence, v.receipt.encode()))
        .collect::<Vec<_>>();
    let prepared = operator
        .balances
        .prepare(
            operator.store.load_current().unwrap(),
            operator.registration.clone(),
        )
        .unwrap();
    rotate_epoch(&mut operator, 0);
    operator.pay(1, 2, 1).unwrap();
    assert_eq!(operator.store.outgoing_entry_count(0).unwrap(), 1);
    assert_eq!(operator.store.outgoing_entry_count(1).unwrap(), 1);
    operator
        .finish_prepared(prepared, &mut TestRng::new(71))
        .unwrap();

    for restart in [false, true] {
        if restart {
            drop(operator);
            operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        }
        assert_eq!(operator.store.outgoing_entry_count(0).unwrap(), 0);
        assert_eq!(operator.store.outgoing_entry_count(1).unwrap(), 1);
        let retry = operator
            .accept_send(authorization.clone(), entries.clone())
            .unwrap()
            .into_accepted();
        assert_eq!(retry.acceptance.encode(), acceptance);
        assert_eq!(
            operator
                .incoming_payments(&recipient, 0, 10)
                .unwrap()
                .into_iter()
                .map(|v| (v.sequence, v.receipt.encode()))
                .collect::<Vec<_>>(),
            receipts
        );
        let evidence = operator.committed_entry(&payer, &recipient, 0).unwrap();
        assert_eq!(
            evidence
                .lookup
                .resolve::<Sha256>(&evidence.change_root, &payer, &recipient)
                .unwrap(),
            (5, 2)
        );
    }
    operator.pay(1, 2, 2).unwrap();
    operator.complete_close(72).unwrap();
    let evidence = operator
        .committed_entry(&recipient, &operator.wallets[2].public_key(), 1)
        .unwrap();
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(
                &evidence.change_root,
                &recipient,
                &operator.wallets[2].public_key(),
            )
            .unwrap(),
        (3, 2)
    );
}

#[test]
fn committed_entry_serves_the_retained_close() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let receiver = operator.wallets[1].public_key();
    operator.pay(0, 1, 7).unwrap();
    let epoch = start_current_close(&mut operator).unwrap().epoch;
    operator.wait_for_closes().unwrap();

    // The credited edge resolves to its committed terminal entry.
    let evidence = operator.committed_entry(&payer, &receiver, epoch).unwrap();
    let change_root = evidence.change_root;
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(&evidence.change_root, &payer, &receiver)
            .unwrap(),
        (7, 1)
    );

    // A changed credit-only row resolves the reverse edge through its empty vector, and
    // a payer outside the close resolves through ordered change-vector absence: both
    // land on the canonical zero entry.
    let evidence = operator.committed_entry(&receiver, &payer, epoch).unwrap();
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(&evidence.change_root, &receiver, &payer)
            .unwrap(),
        (0, 0)
    );
    let idle = operator.wallets[3].public_key();
    let evidence = operator.committed_entry(&idle, &receiver, epoch).unwrap();
    assert_eq!(
        evidence
            .lookup
            .resolve::<Sha256>(&evidence.change_root, &idle, &receiver)
            .unwrap(),
        (0, 0)
    );

    // Close evidence remains available after the operational account versions are pruned.
    let close_successor = |operator: &mut Operator| {
        operator.pay(0, 2, 1).unwrap();
        start_current_close(operator).unwrap();
        operator.wait_for_closes().unwrap();
    };
    let served = |operator: &Operator| {
        let evidence = operator.committed_entry(&payer, &receiver, epoch).unwrap();
        assert_eq!(evidence.change_root, change_root);
        assert_eq!(
            evidence
                .lookup
                .resolve::<Sha256>(&evidence.change_root, &payer, &receiver)
                .unwrap(),
            (7, 1)
        );
    };
    close_successor(&mut operator);
    served(&operator);
    for _ in 1..3 {
        close_successor(&mut operator);
        served(&operator);
    }
    close_successor(&mut operator);
    let retained = operator.committed_entry(&payer, &receiver, epoch).unwrap();
    assert_eq!(retained.change_root, change_root);
    assert_eq!(
        retained
            .lookup
            .resolve::<Sha256>(&change_root, &payer, &receiver)
            .unwrap(),
        (7, 1)
    );
}

#[test]
fn completed_close_event_is_replayable() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let epoch = start_current_close(&mut operator).unwrap().epoch;
    let first = loop {
        if let Some(event) = operator.poll_close(epoch).unwrap() {
            break event;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(matches!(first, CloseEvent::Finished(ref close) if close.epoch == epoch));

    let replay = operator.poll_close(epoch).unwrap();
    assert!(matches!(replay, Some(CloseEvent::Finished(close)) if close.epoch == epoch));
}

#[test]
fn batched_send_survives_retry_and_closes() {
    let mut operator = operator();
    let context = operator.registration.context.payment().clone();
    let (send, entries) = operator
        .sign_send(
            0,
            &[
                (operator.wallets[1].public_key(), 2),
                (operator.wallets[2].public_key(), 3),
                (eve_identity().key, 1),
            ],
        )
        .unwrap();

    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    assert_eq!(first.total, 6);
    assert_eq!(first.acceptance.entries.len(), 3);
    first.acceptance.verify(&context).unwrap();
    assert!(
        first
            .acceptance
            .receipts()
            .all(|receipt| receipt.ack == first.acceptance.ack)
    );
    let retry = operator.accept_send(send, entries).unwrap().into_accepted();
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(retry.acceptance, first.acceptance);

    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 3);
    let balance = |name: &str| {
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == name)
            .unwrap()
            .balance
    };
    assert_eq!(balance("Alice"), INITIAL_BALANCE - 6);
    assert_eq!(balance("Bob"), INITIAL_BALANCE + 2);
    assert_eq!(balance("Carol"), INITIAL_BALANCE + 3);

    // The close replay walks the payer's endpoint once per batch and each entry's edge step.
    let epoch = start_current_close(&mut operator).unwrap().epoch;
    let event = loop {
        if let Some(event) = operator.poll_close(epoch).unwrap() {
            break event;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(matches!(event, CloseEvent::Finished(ref close) if close.epoch == epoch));
    assert_eq!(
        operator.payment_head(&eve_identity().key).unwrap().balance,
        1
    );
}

#[test]
fn registered_empty_epoch_survives_restart_and_finalizes() {
    for cut in 0..3 {
        deterministic::Runner::default().start(|context| async move {
            let chain = Chain::new(&context).await;
            let database = TempDatabase::new();
            let request = {
                let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
                assert_eq!(operator.automatic_epoch().unwrap(), None);
                let request = operator.signed_registration().unwrap();
                if cut == 1 {
                    assert!(chain.try_register(&mut operator).await.is_some());
                } else if cut == 2 {
                    chain.register(&mut operator).await;
                }
                request
            };
            let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
            assert_eq!(operator.signed_registration().unwrap(), request);
            chain.register(&mut operator).await;
            operator.start_close(0).unwrap();
            let events = operator.wait_for_closes().unwrap();
            match events.as_slice() {
                [CloseEvent::Finished(close)] => assert_eq!(close.epoch, 0),
                [CloseEvent::Failed { error, .. }] => panic!("{error}"),
                _ => panic!("expected exactly one close"),
            }
            let result = operator.balances.stored_result(0).unwrap().unwrap();
            assert_eq!(result.rows, 0);
            assert_eq!(result.withdrawal_total, 0);
            for wallet in &operator.wallets {
                assert_eq!(
                    operator.payment_head(&wallet.public_key()).unwrap().balance,
                    100
                );
            }
            chain.admit(&result).await;
            let status = chain.status().await;
            assert!(!status.hard_faulted);
            assert_eq!(status.custody, 400);
        });
    }
}

#[test]
fn completed_close_event_survives_operator_restart() {
    let database = TempDatabase::new();
    let epoch = {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 1).unwrap();
        let epoch = start_current_close(&mut operator).unwrap().epoch;
        operator.wait_for_closes().unwrap();
        epoch
    };

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(matches!(
        recovered.poll_close(epoch).unwrap(),
        Some(CloseEvent::Finished(close)) if close.epoch == epoch
    ));
}

#[test]
fn exact_close_retry_does_not_cut_the_successor_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    let first = start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    operator.pay(2, 3, 7).unwrap();
    let retry = operator.start_close(first.epoch).unwrap();
    release.send(()).unwrap();
    operator.wait_for_closes().unwrap();

    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(operator.store.epoch().unwrap(), first.epoch + 1);
}

#[test]
fn close_retry_survives_operator_restart() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        rotate_epoch(&mut operator, 0);
        operator.pay(2, 3, 7).unwrap();
    }

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let replay = recovered.start_close(0).unwrap();
    assert_eq!(replay.epoch, 0);
    assert_eq!(recovered.store.epoch().unwrap(), 1);
    recovered.wait_for_closes().unwrap();
}

/// The continuous driver recovers an adopted close near its fixed admission
/// deadline without an agent RPC.
#[test]
fn registered_epoch_restart_resumes_the_cut_and_admits() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let chain = Chain::new(&context).await;
        let record = {
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();

            assert_eq!(operator.automatic_epoch().unwrap(), None);

            // The first send triggers the registration before it is accepted,
            // so adopt the assigned deadlines and then take the payment.
            let record = chain
                .try_register(&mut operator)
                .await
                .expect("the registration earned no record");
            operator.adopt_registration(&record).unwrap();

            assert_eq!(operator.automatic_epoch().unwrap(), Some(0));
            operator.pay(0, 1, 25).unwrap();

            // Killed here: the epoch is registered and adopted, the cut is not.
            record
        };

        // Most of the admission runway passes while the operator is down.
        let height = chain.control.advance(0).await;
        assert!(height + 3 <= record.admission_deadline);
        chain
            .control
            .advance(record.admission_deadline - 3 - height)
            .await;

        let recovered = Arc::new(commonware_utils::sync::Mutex::new(
            Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap(),
        ));
        let backend = client::Client::new(
            chain.control.identity(),
            deployment(),
            vec![SocketAddr::from(([127, 0, 0, 1], 9_800))],
            context.child("driver_client"),
        )
        .unwrap();
        let driver = crate::service::start_close_driver(
            &context,
            backend,
            recovered.clone(),
            Timing::DEFAULT,
        );
        for _ in 0..100 {
            if recovered.lock().status().unwrap().epoch == 1 {
                break;
            }
            context.sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(recovered.lock().status().unwrap().epoch, 1);
        driver.abort();
        let _ = driver.await;
        let mut recovered = Arc::try_unwrap(recovered).ok().unwrap().into_inner();
        assert_eq!(recovered.automatic_epoch().unwrap(), None);
        recovered.wait_for_closes().unwrap();
        assert!(matches!(
            recovered.poll_close(0).unwrap(),
            Some(CloseEvent::Finished(close)) if close.epoch == 0
        ));

        // The durable certified result admits inside the driven window.
        let result = recovered.balances.stored_result(0).unwrap().unwrap();
        chain.admit(&result).await;
    });
}

#[test]
fn close_construction_binds_adopted_deadlines() {
    let mut operator = operator();

    operator
        .observe(&[DepositEvent {
            id: Sha256::hash(&[b"long-window-deposit"]),
            account: wallets()[0].public_key(),
            amount: 5,
        }])
        .unwrap();
    let wallet = wallets().remove(0);
    let request = SignedWithdrawal::sign(
        deployment(),
        operator
            .balances
            .root(operator.registration.context.payment().epoch())
            .unwrap()
            .digest,
        Bytes::copy_from_slice(wallet.public_key().as_ref()),
        amount(5),
        500,
        wallet.signer(),
    );
    operator.apply_withdrawal(request).unwrap();

    let admission_deadline = 40;
    let challenge_deadline = admission_deadline + 420;
    let replacement = operator
        .protocol
        .registration_at(
            0,
            operator.registration.deposits.clone(),
            operator.registration.withdrawals.clone(),
            operator.registration.context.predecessor_liability(),
            admission_deadline,
            challenge_deadline,
        )
        .unwrap();
    let deposits_root = replacement.deposits.root::<Sha256>().unwrap();
    operator
        .adopt_registration(&RegistrationRecord {
            epoch: 0,
            predecessor_liability: operator.registration.context.predecessor_liability(),
            anchor: *replacement.context.payment().anchor(),
            admission_deadline,
            challenge_deadline,
            deposits_root,

            withdrawals_root: replacement.withdrawals.root::<Sha256>().unwrap(),
            admitted: None,
        })
        .unwrap();

    let result = operator.complete_close(45).unwrap();
    assert_eq!(result.context.payment().epoch(), 0);

    assert_eq!(result.context.admission_deadline(), admission_deadline);
    assert_eq!(result.context.challenge_deadline(), challenge_deadline);
    assert_eq!(result.withdrawal_total, 5);
}

#[test]
fn close_request_rejects_an_unstarted_noncurrent_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();

    assert!(operator.start_close(1).is_err());
    assert_eq!(operator.store.epoch().unwrap(), 0);
    assert!(!operator.store.has_close_job(1).unwrap());
}

#[test]
fn intake_stops_before_the_terminal_clock_exhausts() {
    let mut operator = operator();
    operator.pay(0, 1, 1).unwrap();
    let terminal_epoch = crate::protocol::TERMINAL_EPOCH;
    operator.registration = operator
        .protocol
        .registration(
            terminal_epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.current_liability().unwrap(),
        )
        .unwrap();

    assert!(
        operator
            .payment_head(&operator.wallets[0].public_key())
            .is_err()
    );
    assert!(operator.validate_close_start(terminal_epoch).is_err());
    assert!(operator.signed_registration().is_err());
    assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
}

fn operator_at_clock_horizon(epoch: u64) -> Operator {
    let mut operator = operator();
    operator.registration = operator
        .protocol
        .registration(
            epoch,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.current_liability().unwrap(),
        )
        .unwrap();
    let connection = rusqlite::Connection::open(operator.store.database_path()).unwrap();
    connection
        .execute(
            "UPDATE operator_meta SET epoch = ?1, payment_context = ?2 WHERE singleton = 1",
            rusqlite::params![
                i64::try_from(epoch).unwrap(),
                operator.registration.context.payment().encode().as_ref()
            ],
        )
        .unwrap();
    operator
}

#[test]
fn balance_intake_stops_while_the_current_epoch_can_still_close() {
    let epoch = crate::protocol::TERMINAL_EPOCH - 2;
    let mut operator = operator_at_clock_horizon(epoch);
    assert!(
        operator
            .payment_head(&operator.wallets[0].public_key())
            .is_err()
    );
    assert_eq!(operator.signed_registration().unwrap().epoch, epoch);
    operator.validate_close_start(epoch).unwrap();
    assert!(operator.snapshot().unwrap().payments.is_empty());
}

#[test]
fn amountless_close_outlives_amount_intake_at_the_clock_horizon() {
    let epoch = crate::protocol::TERMINAL_EPOCH - 1;
    let mut operator = operator_at_clock_horizon(epoch);
    assert!(
        operator
            .ensure_withdrawal_intake_horizon(&amount(1))
            .is_err()
    );
    operator
        .ensure_withdrawal_intake_horizon(&WithdrawalAction::Close)
        .unwrap();
    assert_eq!(operator.signed_registration().unwrap().epoch, epoch);
    operator.validate_close_start(epoch).unwrap();
}

#[test]
fn withdrawal_retry_survives_epoch_cutover() {
    let mut operator = operator();
    let first = operator.withdraw(0, amount(25)).unwrap();
    let request = operator.store.load_current().unwrap().withdrawals[0]
        .request
        .clone();
    rotate_epoch(&mut operator, 0);

    let retry = operator.apply_withdrawal(request).unwrap();
    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.account, first.account);
    assert_eq!(retry.action, first.action);
}

#[test]
fn close_authorization_response_loss_retries_after_cutover_and_restart() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let first = operator.withdraw(0, WithdrawalAction::Close).unwrap();
    let request = operator.store.load_current().unwrap().withdrawals[0]
        .request
        .clone();
    rotate_epoch(&mut operator, 0);
    drop(operator);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    recovered.wait_for_closes().unwrap();
    let retry = recovered.apply_withdrawal(request).unwrap();
    assert_eq!(retry.epoch, first.epoch);
    assert_eq!(retry.account, first.account);
    assert_eq!(retry.action, WithdrawalAction::Close);
    assert_eq!(recovered.status().unwrap().epoch, 1);
}

#[test]
fn staged_close_keeps_incoming_and_outgoing_activity_live_until_cutover() {
    let mut operator = operator();
    operator.withdraw(1, WithdrawalAction::Close).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 400);
    assert_eq!(
        operator
            .payment_head(&operator.wallets[1].public_key())
            .unwrap()
            .balance,
        100
    );

    let receiver = operator.wallets[1].public_key();
    let (incoming, incoming_entries) = operator.sign_send(0, &[(receiver.clone(), 7)]).unwrap();
    assert!(
        operator
            .send_requires_epoch_registration(&incoming, &incoming_entries)
            .unwrap()
    );
    operator
        .accept_send(incoming, incoming_entries)
        .unwrap()
        .into_accepted();

    let (outgoing, outgoing_entries) = operator
        .sign_send(1, &[(operator.wallets[2].public_key(), 12)])
        .unwrap();
    operator
        .accept_send(outgoing, outgoing_entries)
        .unwrap()
        .into_accepted();

    let data = operator.store.load_current().unwrap();
    let bob = data
        .accounts
        .iter()
        .find(|account| account.key == receiver)
        .unwrap();
    assert_eq!(bob.current, 95);
    assert_eq!(
        operator
            .store
            .payer_endpoint(&receiver)
            .unwrap()
            .cumulative_debit,
        12
    );
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();

    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.current_liability().unwrap(), 305);
    assert!(operator.store.current_account(&receiver).unwrap().is_none());
    let frozen = operator.store.epoch_reader().load(0).unwrap();
    let bob = frozen
        .accounts
        .iter()
        .find(|account| account.key == receiver)
        .unwrap();
    assert_eq!(bob.current, 0);
    assert_eq!(frozen.withdrawals[0].applied_amount, Some(95));

    let result = operator.balances.complete(prepared, 44).unwrap();
    assert_eq!(result.withdrawal_total, 95);
    assert_eq!(
        result.withdrawal_claims[0]
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        95
    );
    operator
        .store
        .finish_close(&result, operator.genesis_root)
        .unwrap();
}

#[test]
fn close_can_spend_to_zero_without_creating_withdrawal_work() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.withdraw(0, WithdrawalAction::Close).unwrap();
    operator.pay(0, 1, 100).unwrap();

    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.current_liability().unwrap(), 400);

    let result = operator.balances.complete(prepared, 45).unwrap();
    assert_eq!(result.withdrawal_total, 0);
    assert_eq!(
        result.withdrawal_claims[0]
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        0
    );
    operator
        .store
        .finish_close(&result, operator.genesis_root)
        .unwrap();
    assert!(operator.store.withdrawal_evidence(&account).is_err());
}

#[test]
fn payment_recreates_a_closed_identity_as_a_virtual_balance() {
    let mut operator = operator();
    let closed = operator.wallets[1].public_key();
    operator.withdraw(1, WithdrawalAction::Close).unwrap();
    start_current_close(&mut operator).unwrap();
    operator.wait_for_closes().unwrap();
    assert!(operator.store.current_account(&closed).unwrap().is_none());

    let accepted = operator.pay(0, 1, 7).unwrap();
    assert_eq!(accepted.epoch, 1);
    operator.pay(2, operator.wallet_count(), 5).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 300);
    assert!(operator.payment_head(&closed).is_err());
    assert!(operator.payment_head(&eve_identity().key).is_err());

    start_current_close(&mut operator).unwrap();
    operator.wait_for_closes().unwrap();
    assert_eq!(operator.payment_head(&closed).unwrap().balance, 7);
    assert_eq!(
        operator.payment_head(&eve_identity().key).unwrap().balance,
        5
    );
    assert_eq!(operator.pay(1, 3, 1).unwrap().epoch, 2);
    assert_eq!(operator.store.current_liability().unwrap(), 300);
}

#[test]
fn invalid_requests_are_rejected_before_epoch_registration() {
    let operator = operator();
    let (invalid, invalid_entries) = operator
        .sign_send(0, &[(operator.wallets[1].public_key(), 101)])
        .unwrap();

    assert!(
        operator
            .send_requires_epoch_registration(&invalid, &invalid_entries)
            .is_err()
    );
    assert!(operator.validate_close_start(0).is_err());
}

#[test]
fn unknown_payment_commit_fences_the_connection() {
    let mut operator = operator();
    operator.store.fail_next_payment_commit();
    let error = match operator.pay(0, 1, 10) {
        Ok(_) => panic!("unknown payment commit was acknowledged"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("payment commit outcome is unknown"));
    assert!(operator.fault().is_some());
    assert!(operator.pay(0, 1, 1).is_err());
    assert!(operator.snapshot().is_err());
    assert!(operator.poll_close(0).is_err());
}

#[test]
fn payment_write_failure_fences_the_connection_and_rolls_back() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    operator.store.fail_next_payment_write();

    let error = match operator.pay(0, 1, 10) {
        Ok(_) => panic!("failed payment write was acknowledged"),
        Err(error) => error,
    };
    assert!(!format!("{error:#}").is_empty());
    assert!(operator.fault().is_some());
    assert!(operator.snapshot().is_err());
    drop(operator);

    let recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let snapshot = recovered.snapshot().unwrap();
    assert!(snapshot.payments.is_empty());
    assert!(
        snapshot
            .accounts
            .iter()
            .all(|account| account.balance == 100)
    );
}

#[test]
fn poisoned_connection_rejects_withdrawal_preflight() {
    let mut operator = operator();
    operator.withdraw(0, amount(1)).unwrap();
    let request = operator.store.load_current().unwrap().withdrawals[0]
        .request
        .clone();
    operator.store.fail_next_payment_write();
    assert!(operator.pay(1, 2, 1).is_err());

    let error = match operator.staged_withdrawal(&request) {
        Ok(_) => panic!("withdrawal preflight queried a poisoned connection"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("SQLite connection is unusable"));
}

#[test]
fn rejected_payment_keeps_the_connection_usable() {
    let mut operator = operator();

    assert!(operator.pay(0, 1, 101).is_err());
    assert!(operator.fault().is_none());
    operator.pay(0, 1, 1).unwrap();
}

#[test]
fn unknown_deposit_commit_fences_the_connection() {
    let mut operator = operator();
    operator.store.fail_next_deposit_commit();
    let error = match operator.deposit(0, 10) {
        Ok(_) => panic!("unknown deposit commit was acknowledged"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("deposit commit outcome is unknown"));
    assert!(operator.fault().is_some());
    assert!(operator.deposit(0, 1).is_err());
    assert!(operator.snapshot().is_err());
    assert!(operator.poll_close(0).is_err());
}

#[test]
fn unknown_cutover_commit_fences_the_connection_before_balance_read() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(24))
        .unwrap();

    operator.pay(1, 2, 1).unwrap();
    operator.store.fail_next_cutover_commit();
    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("unknown cutover commit was acknowledged"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("epoch cutover commit outcome is unknown"));
    assert!(operator.store_fault.is_some());
    assert!(operator.payment_head(&eve_identity().key).is_err());
    assert!(operator.snapshot().is_err());
}

#[test]
fn cutover_reuses_the_incrementally_maintained_liability() {
    let mut operator = operator();
    assert_eq!(operator.registration.context.predecessor_liability(), 400);
    assert_eq!(operator.store.current_liability().unwrap(), 400);

    operator.deposit(0, 10).unwrap();
    assert_eq!(operator.registration.context.predecessor_liability(), 400);
    assert_eq!(operator.store.current_liability().unwrap(), 410);
    operator.pay(0, 1, 5).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 410);
    operator.pay(2, operator.wallet_count(), 25).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 410);

    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.registration.context.predecessor_liability(), 410);
}

#[test]
fn cutover_does_not_materialize_account_state() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let rows = operator.store.account_version_count().unwrap();
    let changes = operator.store.total_changes();
    let plan = operator
        .store
        .account_lookup_plan(&operator.wallets[0].public_key())
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("account_states_key_epoch")),
        "point lookup did not use the account-history index: {plan:?}"
    );
    assert!(
        plan.iter().all(|step| !step.contains("SCAN state")),
        "point lookup scanned account history: {plan:?}"
    );

    rotate_epoch(&mut operator, 0);

    assert_eq!(operator.store.total_changes() - changes, 2);
    assert_eq!(operator.store.account_version_count().unwrap(), rows);
    operator.pay(1, 0, 5).unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), rows + 2);
}

#[test]
fn finalization_prunes_obsolete_balance_versions() {
    let mut operator = operator();

    operator.pay(1, 2, 1).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, prepared.epoch());
    operator
        .finish_prepared(prepared, &mut TestRng::new(40))
        .unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 4);

    operator
        .pay(0, operator.wallet_count(), INITIAL_BALANCE)
        .unwrap();
    operator.pay(1, 2, 10).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, prepared.epoch());

    assert_eq!(operator.store.account_version_count().unwrap(), 8);
    let frozen = operator.store.epoch_reader().load(1).unwrap();
    assert!(
        frozen
            .accounts
            .iter()
            .any(|account| { account.name == operator.wallets[0].name && account.current == 0 })
    );

    operator
        .finish_prepared(prepared, &mut TestRng::new(41))
        .unwrap();

    assert_eq!(operator.store.account_version_count().unwrap(), 4);
    let drained = operator.wallets[0].name;
    let gone = |data: EpochData| data.accounts.iter().all(|account| account.name != drained);
    assert!(gone(operator.store.load_current().unwrap()));

    for epoch in 2..=3 {
        operator.pay(1, 2, 1).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        assert_eq!(prepared.epoch(), epoch);
        rotate_epoch(&mut operator, epoch);
        operator
            .finish_prepared(prepared, &mut TestRng::new(40 + epoch))
            .unwrap();
        assert_eq!(operator.store.account_version_count().unwrap(), 4);
    }
    assert!(gone(operator.store.load_current().unwrap()));
}

#[test]
fn pruning_ignores_unfinalized_successor_versions() {
    let mut operator = operator();

    operator.pay(1, 2, 1).unwrap();
    let data = operator.store.load_current().unwrap();
    let first = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, first.epoch());

    operator
        .pay(0, operator.wallet_count(), INITIAL_BALANCE)
        .unwrap();
    let second_registration = operator.registration.clone();
    rotate_epoch(&mut operator, second_registration.context.payment().epoch());
    operator.deposit(0, 5).unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 7);

    operator
        .finish_prepared(first, &mut TestRng::new(42))
        .unwrap();
    assert_eq!(operator.store.account_version_count().unwrap(), 7);

    let frozen = operator.store.epoch_reader().load(1).unwrap();
    assert!(
        frozen
            .accounts
            .iter()
            .any(|account| { account.name == operator.wallets[0].name && account.current == 0 })
    );
    let second = operator
        .balances
        .prepare(frozen, second_registration)
        .unwrap();
    operator
        .finish_prepared(second, &mut TestRng::new(43))
        .unwrap();

    // The unfinalized deposit remains live after the drained finalized baseline retires.
    assert_eq!(operator.store.account_version_count().unwrap(), 5);
    let recreated = operator
        .store
        .current_account(&operator.wallets[0].public_key())
        .unwrap()
        .unwrap();
    assert_eq!(recreated.current, 5);
}

#[test]
fn frozen_epoch_scan_does_not_walk_account_history() {
    let operator = operator();
    let plan = operator.store.epoch_account_plan(0).unwrap();
    assert!(
        plan.iter().any(|step| step.contains("SCAN identity")),
        "epoch reconstruction is not driven by account identities: {plan:?}"
    );
    assert!(
        plan.iter().all(|step| !step.contains("SCAN state")),
        "epoch reconstruction walks historical account versions: {plan:?}"
    );
}

#[test]
fn ephemeral_terminal_database_uses_wal() {
    let operator = operator();
    assert_eq!(operator.store.journal_mode().unwrap(), "wal");
}

#[test]
fn non_wal_sqlite_sources_are_rejected() {
    let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(format!(
        "file:commonware-terminal-{}-{id}?mode=memory&cache=shared",
        std::process::id()
    ));
    let error = match Operator::open(&path, NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("non-WAL database was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("WAL"));
}

#[test]
fn ephemeral_database_lives_until_the_last_reader_owner() {
    let operator = operator();
    let path = operator.store.database_path();
    let reader = operator.store.epoch_reader();
    assert!(path.exists());

    drop(operator);
    assert!(path.exists());

    drop(reader);
    assert!(!path.exists());
}

#[test]
fn boundary_membership_controls_spending_after_zero_balance() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();

    // Boundary membership keeps a drained account eligible to receive and spend in the epoch.
    operator.pay(1, 0, 10).unwrap();
    operator.pay(0, operator.wallet_count(), 10).unwrap();
    assert_eq!(operator.snapshot().unwrap().payments.len(), 3);

    operator.complete_close(46).unwrap();
    assert!(
        operator
            .store
            .current_account(&operator.wallets[0].public_key())
            .unwrap()
            .is_none()
    );

    // Once absent at the next boundary, a credit recreates virtual value but cannot make the
    // recipient a payer until that first positive successor is admitted.
    operator.pay(1, 0, 5).unwrap();
    assert_eq!(
        operator
            .store
            .current_account(&operator.wallets[0].public_key())
            .unwrap()
            .unwrap()
            .current,
        5
    );
    assert!(operator.pay(0, operator.wallet_count(), 1).is_err());
    operator.complete_close(47).unwrap();
    assert_eq!(
        operator
            .payment_head(&operator.wallets[0].public_key())
            .unwrap()
            .balance,
        5
    );
    assert_eq!(
        operator.pay(0, operator.wallet_count(), 5).unwrap().epoch,
        2
    );
}

#[test]
fn empty_close_rejection_keeps_the_operator_live() {
    let mut operator = operator();
    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("empty epoch was closed"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("nothing to close"));
    assert!(operator.fault().is_none());
    assert_eq!(operator.pay(0, 1, 1).unwrap().epoch, 0);
}

#[test]
fn rejected_deposit_does_not_change_the_epoch_anchor() {
    let mut operator = operator();
    let large = i64::MAX as u64 - 400;
    operator.deposit(0, large).unwrap();

    let error = match operator.deposit(1, 1) {
        Ok(_) => panic!("overflowing deposit was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("live liability"));
    assert!(operator.fault().is_none());
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Bob")
            .unwrap()
            .balance,
        100
    );
}

#[test]
fn stale_same_epoch_anchor_is_rejected_without_mutation() {
    let mut operator = operator();
    let stale = operator.registration.context.payment().clone();
    operator.deposit(0, 10).unwrap();
    let receiver = operator.wallets[2].public_key();
    let (send, entries) = sign_send_at(
        &stale,
        &operator.wallets[1],
        &Endpoint {
            cumulative_debit: 0,
            seq: 0,
            entries: Vec::new(),
        },
        &[(receiver, 1)],
    )
    .unwrap();

    let error = match operator
        .store
        .accept_send(&stale, &operator.protocol, send, &entries)
    {
        Ok(_) => panic!("stale payment anchor was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("payment anchor is stale"));
    let snapshot = operator.snapshot().unwrap();
    assert!(snapshot.payments.is_empty());
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == operator.wallets[1].name)
            .unwrap()
            .balance,
        100
    );
}

#[test]
fn cutover_accepts_successor_payment_before_predecessor_root_preparation() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    let close = start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    let successor = operator.pay(1, 0, 5).unwrap();
    assert_eq!(successor.epoch, 1);
    assert!(operator.close_in_progress());
    release.send(()).unwrap();
    let events = operator.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Finished(finished)] if finished.epoch == close.epoch
    ));
    let snapshot = operator.snapshot().unwrap();
    assert_eq!(snapshot.payments.len(), 1);
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap()
            .balance,
        95
    );
}

#[test]
fn close_backlog_is_bounded_before_cutover() {
    let mut operator = operator();
    let (started, release) = operator.pause_next_close();
    for epoch in 0..MAX_PENDING_CLOSES {
        operator.pay(epoch % 2, (epoch + 1) % 2, 1).unwrap();
        let close = start_current_close(&mut operator).unwrap();
        assert_eq!(close.epoch, epoch as u64);
        if epoch == 0 {
            started.recv_timeout(Duration::from_secs(1)).unwrap();
        } else {
            assert!(close.queued);
        }
    }
    operator.pay(0, 1, 1).unwrap();
    let epoch = operator.snapshot().unwrap().epoch;
    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("close backlog exceeded its bound"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("backlog"));
    assert_eq!(operator.snapshot().unwrap().epoch, epoch);
    assert!(operator.fault().is_none());

    release.send(()).unwrap();
    assert_eq!(
        operator.wait_for_closes().unwrap().len(),
        MAX_PENDING_CLOSES
    );
}

#[test]
fn close_scheduler_uses_the_status_epoch_index() {
    let operator = operator();
    let plan = operator.store.close_job_status_query_plan().unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("close_jobs_status_epoch")),
        "unexpected query plan: {plan:?}"
    );
}

#[test]
fn committed_cutover_fences_a_worker_start_failure() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    operator.fail_next_close_spawn();

    let error = match start_current_close(&mut operator) {
        Ok(_) => panic!("injected worker failure was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("operator fenced"));
    assert!(operator.fault().is_some());
    assert!(operator.pay(2, 3, 1).is_err());
    assert_eq!(operator.store.closing_epoch_from(0).unwrap(), None);
}

#[test]
fn worker_panic_fences_the_successor_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    operator.panic_next_close_worker();
    start_current_close(&mut operator).unwrap();

    let events = operator.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Failed { epoch: 0, .. }]
    ));
    assert!(operator.fault().is_some());
    assert!(operator.pay(2, 3, 1).is_err());
}

#[test]
fn finalization_write_failure_fences_the_successor_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    let close = start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    operator
        .store
        .fail_close(close.epoch, "injected finalization failure")
        .unwrap();
    release.send(()).unwrap();

    assert!(operator.wait_for_closes().is_err());
    assert!(operator.fault().is_some());
    assert!(operator.pay(2, 3, 1).is_err());
}

#[test]
fn queued_worker_start_failure_fences_after_predecessor_finalization() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    operator.pay(2, 3, 7).unwrap();
    assert!(start_current_close(&mut operator).unwrap().queued);
    operator.fail_next_close_spawn();
    release.send(()).unwrap();

    assert!(operator.wait_for_closes().is_err());
    assert!(operator.fault().is_some());
    assert!(operator.pay(0, 1, 1).is_err());
    assert!(
        operator
            .store
            .failed_close()
            .unwrap()
            .unwrap()
            .starts_with("epoch 1:")
    );
}

#[test]
fn older_finalization_preserves_a_descendant_fault() {
    let mut operator = operator();
    operator.pay(0, 1, 10).unwrap();
    let (started, release) = operator.pause_next_close();
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();

    operator.pay(2, 3, 7).unwrap();
    assert!(start_current_close(&mut operator).unwrap().queued);
    let descendant_fault = "injected descendant fault".to_string();
    operator.store.fail_close(1, &descendant_fault).unwrap();
    operator.close_fault = Some(descendant_fault.clone());
    release.send(()).unwrap();

    loop {
        if let Some(event) = operator.poll_close(0).unwrap() {
            assert!(matches!(event, CloseEvent::Finished(finished) if finished.epoch == 0));
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(operator.fault(), Some(descendant_fault.as_str()));
    assert!(!operator.close_in_progress());
    assert!(operator.pay(0, 1, 1).is_err());
}

#[test]
fn recovery_finishes_an_unfailed_ancestor_below_a_descendant_fault() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        let (started, release) = operator.pause_next_close();
        start_current_close(&mut operator).unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        operator.pay(2, 3, 7).unwrap();
        assert!(start_current_close(&mut operator).unwrap().queued);
        operator.pay(0, 1, 3).unwrap();
        assert!(start_current_close(&mut operator).unwrap().queued);
        operator
            .store
            .fail_close(2, "injected descendant fault")
            .unwrap();
        drop(release);
    }

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.fault().is_some());
    assert!(recovered.close_in_progress());
    let events = recovered.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Finished(first), CloseEvent::Finished(second)]
            if first.epoch == 0 && second.epoch == 1
    ));
    assert!(recovered.fault().is_some());
    assert!(recovered.pay(0, 1, 1).is_err());
}

#[test]
fn cut_and_successor_payment_recover_before_predecessor_preparation() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        rotate_epoch(&mut operator, 0);
        let successor = operator.pay(2, 3, 7).unwrap();
        assert_eq!(successor.epoch, 1);
    }

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.close_in_progress());
    assert_eq!(recovered.snapshot().unwrap().payments.len(), 1);
    assert!(recovered.pay(0, 1, 1).is_err());
    let events = recovered.wait_for_closes().unwrap();
    assert!(matches!(
        events.as_slice(),
        [CloseEvent::Finished(finished)] if finished.epoch == 0
    ));
    assert_eq!(recovered.snapshot().unwrap().epoch, 1);
    assert_eq!(recovered.pay(0, 1, 1).unwrap().epoch, 1);
}

#[test]
fn recovery_rejects_unreplayed_current_state() {
    let database = TempDatabase::new();
    {
        let _operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states SET current_balance = 99
             WHERE epoch = 0 AND public_key = (
                 SELECT public_key FROM account_identities WHERE name = 'Alice'
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("corrupt operator state was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("SQLite balance drift"));
}

#[test]
fn recovery_rejects_same_liability_state_substitution() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states
             SET current_balance = current_balance + CASE
                 WHEN public_key = (
                     SELECT public_key FROM account_identities WHERE name = 'Alice'
                 ) THEN -1 ELSE 1 END
             WHERE epoch = 0 AND public_key IN (
                 SELECT public_key FROM account_identities WHERE name IN ('Alice', 'Bob')
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("same-liability predecessor substitution was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("predecessor root"));
}

#[test]
fn pending_genesis_close_rejects_same_liability_predecessor_substitution() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        rotate_epoch(&mut operator, 0);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states
             SET predecessor_balance = predecessor_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END,
                 current_balance = current_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END
             WHERE epoch = 0 AND public_key IN (
                 SELECT public_key FROM account_identities WHERE name IN ('Alice', 'Bob')
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(matches!(
        recovered.wait_for_closes().unwrap().as_slice(),
        [CloseEvent::Failed { epoch: 0, error }] if error.contains("predecessor root")
    ));
    assert!(recovered.store.failed_close().unwrap().is_some());
}

#[test]
fn predecessor_root_rejection_is_durable() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 1);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE account_states
             SET predecessor_balance = predecessor_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END,
                 current_balance = current_balance + CASE
                     WHEN public_key = (
                         SELECT public_key FROM account_identities WHERE name = 'Alice'
                     ) THEN -1 ELSE 1 END
             WHERE epoch = 1 AND public_key IN (
                 SELECT public_key FROM account_identities WHERE name IN ('Alice', 'Bob')
             )",
            [],
        )
        .unwrap();
    drop(connection);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(matches!(
        recovered.wait_for_closes().unwrap().as_slice(),
        [CloseEvent::Failed { epoch: 1, error }] if error.contains("predecessor root")
    ));
    drop(recovered);

    let mut reopened = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(reopened.fault().is_some());
    assert!(reopened.pay(0, 1, 1).is_err());
}

#[test]
fn malformed_predecessor_roots_persist_a_close_fence() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 1);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute(
            "UPDATE settlements SET roots = zeroblob(1) WHERE epoch = 0",
            [],
        )
        .unwrap();
    drop(connection);

    let mut recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(recovered.wait_for_closes().is_err());
    drop(recovered);

    let reopened = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert!(reopened.store.failed_close().unwrap().is_some());
    assert!(!reopened.close_in_progress());
}

#[test]
fn recovery_bounds_close_error_before_materializing_text() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 1).unwrap();
        rotate_epoch(&mut operator, 0);
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    connection
        .execute(
            "UPDATE close_jobs
             SET status = 'failed', error = CAST(zeroblob(1048576) AS TEXT)
             WHERE epoch = 0",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized close error was materialized"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("persisted byte bound"));
}

#[test]
fn recovery_bounds_entry_blobs_before_decoding() {
    let database = TempDatabase::new();
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.pay(0, 1, 10).unwrap();
    }
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    connection
        .execute(
            "UPDATE accepted_entries SET opening = zeroblob(1048576)",
            [],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized entry opening was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("invalid entry opening length"));
}

#[test]
fn recovery_bounds_account_keys_before_decoding() {
    let database = TempDatabase::new();
    let key = {
        let operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        operator.wallets[0].public_key()
    };
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             PRAGMA ignore_check_constraints = ON;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE account_states SET public_key = zeroblob(1048576)
             WHERE public_key = ?1",
            [key.as_ref()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE account_identities SET public_key = zeroblob(1048576)
             WHERE public_key = ?1",
            [key.as_ref()],
        )
        .unwrap();
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("oversized account key was accepted"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("invalid account key length"));
}

#[test]
fn virtual_credit_creates_a_successor_without_a_withdrawal_reserve() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        // Registration precedes the epoch's first receipt, as the service
        // orders it: adopting the chain-assigned deadlines moves the anchor.
        chain.register(&mut operator).await;
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let result = operator.balances.complete(prepared, 8).unwrap();
        assert_eq!(result.withdrawal_total, 0);
        chain.admit(&result).await;
        let status = chain.status().await;
        assert_eq!(status.custody, 400);
        assert_eq!(status.claimable, 0);
        operator
            .store
            .finish_close(&result, operator.genesis_root)
            .unwrap();
        let snapshot = operator.snapshot().unwrap();
        let alice = snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap();
        assert!(!alice.present);
        let eve = operator.payment_head(&eve_identity().key).unwrap();
        assert_eq!(eve.balance, 100);
        assert_eq!(
            eve.opening
                .verify::<Sha256>(&result.roots.successor)
                .unwrap()
                .get(),
            100
        );
    });
}

#[test]
fn virtual_credit_batch_does_not_block_later_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        chain.register(&mut operator).await;
        operator.pay(0, operator.wallet_count(), 10).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let first = operator.balances.complete(prepared, 31).unwrap();
        chain.admit(&first).await;
        let machine_key = crate::chain::state::machine_key(&deployment());
        let Some(Record::Machine(first_machine)) = chain.control.record(machine_key.clone()).await
        else {
            panic!("finalization persists the active machine");
        };
        operator
            .store
            .finish_close(&first, operator.genesis_root)
            .unwrap();

        chain.register(&mut operator).await;
        operator.pay(1, operator.wallet_count(), 20).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let second = operator.balances.complete(prepared, 32).unwrap();
        chain.admit(&second).await;
        assert_eq!(chain.status().await.claimable, 0);
        assert_eq!(chain.status().await.custody, 400);
        let Some(Record::Machine(second_machine)) = chain.control.record(machine_key).await else {
            panic!("finalization persists the active machine");
        };
        assert_eq!(first_machine.len(), second_machine.len());
        operator
            .store
            .finish_close(&second, operator.genesis_root)
            .unwrap();
        assert_eq!(
            operator.payment_head(&eve_identity().key).unwrap().balance,
            30
        );
        assert_eq!(operator.store.current_liability().unwrap(), 400);
    });
}

#[test]
fn finalized_withdrawal_replays_after_a_later_claim() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        operator.withdraw(0, amount(25)).unwrap();
        let first_account = operator.wallets[0].public_key();
        let first_opening = operator.withdrawal_opening(&first_account).unwrap();
        let data = operator.store.load_current().unwrap();
        chain
            .queue_withdrawal(
                data.withdrawals[0].request.clone(),
                vec![first_opening.opening],
            )
            .await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let first = operator.balances.complete(prepared, 33).unwrap();
        chain.admit(&first).await;
        assert_eq!(chain.status().await.claimable, 25);
        operator
            .store
            .finish_close(&first, operator.genesis_root)
            .unwrap();

        let first_batch = first.header.batch_id::<Sha256>();
        let first_claim = first.withdrawal_claims.first().unwrap();
        assert_eq!(first_claim.position(), 0);

        // An unknown batch is an availability signal, never a verdict on the claim.
        assert_eq!(
            chain
                .claim_withdrawal(
                    BatchId::new(Sha256::hash(&[b"unknown-withdrawal-batch"])),
                    first_claim,
                )
                .await,
            None
        );
        let first_output = released(chain.claim_withdrawal(first_batch, first_claim).await);
        assert_eq!(chain.status().await.claimable, 0);

        operator.withdraw(1, amount(30)).unwrap();
        let second_account = operator.wallets[1].public_key();
        let second_opening = operator.withdrawal_opening(&second_account).unwrap();
        let data = operator.store.load_current().unwrap();
        chain
            .queue_withdrawal(
                data.withdrawals[0].request.clone(),
                vec![second_opening.opening],
            )
            .await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let second = operator.balances.complete(prepared, 34).unwrap();
        chain.admit(&second).await;
        assert_eq!(chain.status().await.claimable, 30);

        let second_batch = second.header.batch_id::<Sha256>();
        let second_claim = second.withdrawal_claims.first().unwrap();
        assert_eq!(second_claim.position(), 0);
        assert_ne!(second_batch, first_batch);
        let second_output = released(chain.claim_withdrawal(second_batch, second_claim).await);
        assert_eq!(chain.status().await.claimable, 0);
        assert_eq!(
            released(chain.claim_withdrawal(second_batch, second_claim).await),
            second_output
        );

        // A consumed position replays only for the exact recorded claim: the
        // exact bytes stay provably released through the release record,
        // while a foreign claim against the drained batch releases nothing
        // and never can.
        assert_eq!(
            chain.claim_withdrawal(first_batch, second_claim).await,
            None
        );
        assert_eq!(
            released(chain.claim_withdrawal(first_batch, first_claim).await),
            first_output
        );
        assert_eq!(chain.status().await.claimable, 0);
    });
}

#[test]
fn virtual_credit_survives_restart_without_claim_work() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(18))
        .unwrap();
    drop(operator);

    let recovered = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(
        recovered.payment_head(&eve_identity().key).unwrap().balance,
        100
    );
    assert_eq!(recovered.store.current_liability().unwrap(), 400);
    assert_eq!(recovered.balances.startup_work().unwrap(), (vec![], vec![]));
}

#[test]
fn ordinary_withdrawal_is_included_and_claimable() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let staged = operator.withdraw(0, amount(25)).unwrap();
        assert_eq!(staged.epoch, 0);
        assert_eq!(staged.action, amount(25));
        let snapshot = operator.snapshot().unwrap();
        let alice = snapshot
            .accounts
            .iter()
            .find(|account| account.name == "Alice")
            .unwrap();
        assert_eq!(alice.balance, 75);

        let data = operator.store.load_current().unwrap();
        let request = data.withdrawals[0].request.clone();
        let account = operator.wallets[0].public_key();
        let opening = operator.withdrawal_opening(&account).unwrap();
        chain.queue_withdrawal(request, vec![opening.opening]).await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let result = operator.balances.complete(prepared, 21).unwrap();
        let batch_id = result.header.batch_id::<Sha256>();
        operator
            .store
            .finish_close(&result, operator.genesis_root)
            .unwrap();

        let (claim_epoch, evidence) = operator
            .store
            .withdrawal_evidence(&operator.wallets[0].public_key())
            .unwrap();
        assert_eq!(claim_epoch, epoch);
        assert_eq!(evidence.output().amount(), 25);
        assert_eq!(
            evidence.output().destination().as_ref(),
            operator.wallets[0].public_key().as_ref()
        );
        chain.admit(&result).await;
        let release = released(chain.claim_withdrawal(batch_id, &evidence).await);
        assert_eq!(release.amount, 25);
        assert_eq!(
            release.destination.as_ref(),
            operator.wallets[0].public_key().as_ref()
        );
        assert_eq!(release.amount, evidence.output().amount());
        assert_eq!(&release.destination, evidence.output().destination());
        assert_eq!(
            released(chain.claim_withdrawal(batch_id, &evidence).await,),
            release
        );
    });
}

#[test]
fn offset_boundaries_settle_in_their_registered_epoch() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();
        for (index, value) in [3, 4].into_iter().enumerate() {
            let event = DepositEvent {
                id: Sha256::hash(&[b"offset-deposit", &[index as u8]]),
                account: account.clone(),
                amount: value,
            };
            chain.deposit(event.clone()).await;
            assert_eq!(operator.observe(&[event]).unwrap()[0].epoch, 0);
            if index == 0 {
                operator.withdraw(0, amount(7)).unwrap();
            }
        }
        assert_eq!(operator.registration.deposits.amount_for(&account), 7);
        chain.register(&mut operator).await;
        assert_eq!(operator.payment_head(&account).unwrap().balance, 100);
        assert!(operator.pay(0, 1, 101).is_err());
        operator.pay(0, 1, 5).unwrap();
        rotate_epoch(&mut operator, 0);

        let frozen = operator.store.epoch_reader().load(0).unwrap();
        let recovered = registration_for(&operator.protocol, &frozen).unwrap();
        let prepared = operator.balances.prepare(frozen, recovered).unwrap();
        let result = operator.balances.complete(prepared, 51).unwrap();
        chain.admit(&result).await;
        operator
            .store
            .finish_close(&result, operator.genesis_root)
            .unwrap();
        assert_eq!(operator.payment_head(&account).unwrap().balance, 95);
        assert!(operator.registration.deposits.records().is_empty());
        let release = released(
            chain
                .claim_withdrawal(
                    result.header.batch_id::<Sha256>(),
                    &result.withdrawal_claims[0],
                )
                .await,
        );
        assert_eq!(release.amount, 7);
        assert!(!chain.status().await.hard_faulted);
    });
}

#[test]
fn offset_intake_order_and_restart_preserve_all_deposits() {
    for deposits_first in [false, true] {
        let database = TempDatabase::new();
        let account = wallets()[0].public_key();
        {
            let mut operator =
                Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
            if deposits_first {
                operator.deposit(0, 7).unwrap();
            }
            operator.withdraw(0, amount(7)).unwrap();
            if !deposits_first {
                operator.deposit(0, 7).unwrap();
            }
            assert_eq!(operator.payment_head(&account).unwrap().balance, 100);
        }
        let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
        assert_eq!(operator.registration.deposits.amount_for(&account), 7);
        assert_eq!(operator.payment_head(&account).unwrap().balance, 100);
        operator.deposit(0, 5).unwrap();
        assert_eq!(operator.registration.deposits.amount_for(&account), 12);
        assert_eq!(operator.payment_head(&account).unwrap().balance, 105);
    }
}

#[test]
fn a_withdrawal_can_use_its_epoch_deposit() {
    let mut operator = operator();
    let account = operator.wallets[0].public_key();
    operator.deposit(0, 5).unwrap();
    assert!(operator.withdraw(0, amount(106)).is_err());
    assert_eq!(operator.payment_head(&account).unwrap().balance, 105);
    operator.withdraw(0, amount(101)).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().balance, 4);
}

#[test]
fn queued_withdrawal_uses_the_settled_offset_balance() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();
        async fn close(
            chain: &Chain,
            operator: &mut Operator,
            epoch: u64,
            seed: u64,
        ) -> SettlementResult {
            rotate_epoch(operator, epoch);
            let frozen = operator.store.epoch_reader().load(epoch).unwrap();
            let recovered = registration_for(&operator.protocol, &frozen).unwrap();
            let prepared = operator.balances.prepare(frozen, recovered).unwrap();
            let result = operator.balances.complete(prepared, seed).unwrap();
            chain.admit(&result).await;
            operator
                .store
                .finish_close(&result, operator.genesis_root)
                .unwrap();
            result
        }

        let event = DepositEvent {
            id: Sha256::hash(&[b"queued-offset-deposit"]),
            account: account.clone(),
            amount: 7,
        };
        chain.deposit(event.clone()).await;
        operator.observe(&[event]).unwrap();
        operator.withdraw(0, amount(7)).unwrap();
        chain.register(&mut operator).await;
        let first_close = close(&chain, &mut operator, 0, 54).await;
        assert_eq!(operator.payment_head(&account).unwrap().balance, 100);

        let opening = operator.withdrawal_opening(&account).unwrap();
        let queued = SignedWithdrawal::sign(
            operator.protocol.deployment(),
            opening.root.digest,
            Bytes::copy_from_slice(operator.wallets[0].public_key().as_ref()),
            amount(7),
            50,
            operator.wallets[0].signer(),
        );
        chain
            .queue_withdrawal(queued.clone(), vec![opening.opening])
            .await;
        operator.apply_withdrawal(queued).unwrap();
        assert_eq!(operator.payment_head(&account).unwrap().balance, 93);
        assert!(operator.registration.deposits.records().is_empty());
        chain.register(&mut operator).await;
        let second_close = close(&chain, &mut operator, 1, 55).await;

        assert_eq!(operator.payment_head(&account).unwrap().balance, 93);
        assert!(operator.registration.deposits.records().is_empty());
        assert!(!chain.status().await.hard_faulted);

        // Both withdrawal reserves release.
        for result in [&first_close, &second_close] {
            let release = released(
                chain
                    .claim_withdrawal(
                        result.header.batch_id::<Sha256>(),
                        &result.withdrawal_claims[0],
                    )
                    .await,
            );
            assert_eq!(release.amount, 7);
        }
    });
}

#[test]
fn missing_deposit_is_rejected_at_registration_until_credited() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();

        let event = DepositEvent {
            id: Sha256::hash(&[b"hidden-divergence-deposit"]),
            account,
            amount: 7,
        };
        chain.deposit(event.clone()).await;
        operator.withdraw(0, amount(7)).unwrap();
        assert_eq!(
            operator.signed_registration().unwrap().deposits_root,
            DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
        );
        assert_eq!(chain.try_register(&mut operator).await, None);

        operator.observe(&[event]).unwrap();
        chain.register(&mut operator).await;
    });
}

#[test]
fn divergent_deposit_boundary_is_rejected_without_consuming_the_slot() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();

        // A signer that agrees on the staged view but commits a boundary the
        // chain cannot derive is rejected on the boundary check alone.
        let mut register = operator.signed_registration().unwrap();
        let record = DepositRecord::new(operator.wallets[0].public_key(), 7).unwrap();
        let divergent = DepositBatch::new(vec![record])
            .unwrap()
            .root::<Sha256>()
            .unwrap();
        register.deposits_root = divergent;
        register.signature = operator.protocol.sign_chain_registration(
            register.epoch,
            register.predecessor_liability,
            &register.deposits_root,
            &register.withdrawals,
            register.fee,
        );
        chain
            .control
            .submit(SettlementTx::RegisterEpoch(register))
            .await;
        assert_eq!(
            chain.control.record(registration_key(&deployment())).await,
            None
        );

        // The effect-free rejection leaves the epoch slot open: the honest
        // bytes register the same epoch.
        chain.register(&mut operator).await;
    });
}

#[test]
fn acknowledged_withdrawal_evidence_advances_to_the_next_epoch() {
    let mut operator = operator();
    operator.withdraw(0, amount(25)).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(26))
        .unwrap();
    let first = operator
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();

    operator.withdraw(0, amount(10)).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(27))
        .unwrap();
    assert_eq!(
        operator
            .withdrawal_evidence(&operator.wallets[0].public_key())
            .unwrap()
            .batch_id(),
        first.batch_id()
    );

    let wrong_batch = BatchId::new(Sha256::hash(&[b"wrong-withdrawal-batch"]));
    assert!(
        operator
            .acknowledge_withdrawal_claim(
                wrong_batch,
                &first.witness.request.account().clone(),
                &first.witness.claim
            )
            .is_err()
    );
    let wrong_account = operator.wallets[1].public_key();
    assert!(
        operator
            .acknowledge_withdrawal_claim(first.batch_id(), &wrong_account, &first.witness.claim)
            .is_err()
    );
    let retry = operator
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_eq!(retry.batch_id(), first.batch_id());
    assert_eq!(retry.witness.claim, first.witness.claim);

    operator
        .acknowledge_withdrawal_claim(
            first.batch_id(),
            &first.witness.request.account().clone(),
            &first.witness.claim,
        )
        .unwrap();
    operator
        .acknowledge_withdrawal_claim(
            first.batch_id(),
            &first.witness.request.account().clone(),
            &first.witness.claim,
        )
        .unwrap();
    let second = operator
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_ne!(second.batch_id(), first.batch_id());
    assert_eq!(
        second.witness.request.account().clone(),
        operator.wallets[0].public_key()
    );
    assert_eq!(second.witness.claim.output().amount(), 10);
}

#[test]
fn malformed_admission_does_not_poison_valid_retry() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        chain.register(&mut operator).await;
        operator.pay(0, 1, 1).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .balances
            .prepare(data, operator.registration.clone())
            .unwrap();
        let result = operator.balances.complete(prepared, 25).unwrap();
        let mut malformed = AdmitRequest::from(&result);
        malformed.roots.change.digest = Sha256::hash(&[b"malformed-change-root"]);
        let epoch = malformed.epoch;

        // A rejected admission is effect-free and must not consume or fence
        // the registration slot.
        chain.control.submit(SettlementTx::Admit(malformed)).await;
        assert_eq!(
            chain
                .control
                .record(admitted_key(&deployment(), epoch))
                .await,
            None
        );
        chain.admit(&result).await;
    });
}

#[test]
fn close_removes_the_account_and_claims_the_final_tail() {
    let mut operator = operator();
    let staged = operator.withdraw(0, WithdrawalAction::Close).unwrap();
    assert_eq!(staged.action, WithdrawalAction::Close);
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(22))
        .unwrap();

    let alice = operator
        .snapshot()
        .unwrap()
        .accounts
        .into_iter()
        .find(|account| account.name == "Alice")
        .unwrap();
    assert!(!alice.present);
    let (claim_epoch, evidence) = operator
        .store
        .withdrawal_evidence(&operator.wallets[0].public_key())
        .unwrap();
    assert_eq!(claim_epoch, epoch);
    assert_eq!(evidence.output().amount(), INITIAL_BALANCE);
    assert_eq!(
        evidence.output().destination().as_ref(),
        operator.wallets[0].public_key().as_ref()
    );
}

#[test]
fn deposit_recreates_an_absent_account() {
    let mut operator = operator();
    operator.pay(0, operator.wallet_count(), 100).unwrap();
    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(data, operator.registration.clone())
        .unwrap();
    let epoch = prepared.epoch();
    rotate_epoch(&mut operator, epoch);
    operator
        .finish_prepared(prepared, &mut TestRng::new(9))
        .unwrap();
    operator.deposit(0, 30).unwrap();
    let snapshot = operator.snapshot().unwrap();
    let alice = snapshot
        .accounts
        .iter()
        .find(|account| account.name == "Alice")
        .unwrap();
    assert!(alice.present);
    assert_eq!(alice.balance, 30);
}

#[test]
fn deposit_event_capacity_is_rejected_before_mutation() {
    let mut operator = operator();
    for index in 0..1_024 {
        operator
            .deposit(index % operator.wallet_count(), 1)
            .unwrap();
    }
    let epoch = operator.snapshot().unwrap().epoch;
    let liability = operator.store.current_liability().unwrap();
    let error = match operator.deposit(0, 1) {
        Ok(_) => panic!("deposit event capacity was exceeded"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("deposit event capacity"));
    assert_eq!(operator.snapshot().unwrap().epoch, epoch);
    assert_eq!(operator.store.current_liability().unwrap(), liability);
}

#[test]
fn canonical_fence_releases_a_close_waiting_for_certification() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let (certifier, mailbox) = node::Certifier::new(
            context.child("certifier"),
            node::Config {
                verifier: protocol.verifier(),
                chain: PendingAdmission {
                    records: BTreeMap::new(),
                },
                mailbox_size: NonZeroUsize::new(10).unwrap(),
            },
        );
        let peers = (0..crate::protocol::committee().unwrap().members().len())
            .map(|index| ed25519::PrivateKey::from_seed(index as u64).public_key())
            .collect::<Vec<_>>();
        let handle = certifier.start(inert_channel(peers.clone()));
        let pipeline = node::Pipeline::new(mailbox, &peers, deployment()).unwrap();
        let identities = identities();
        let store = Store::open(Path::new(":memory:"), &identities).unwrap();
        let mut operator = Operator::from_store(
            store,
            identities,
            protocol,
            Some(pipeline),
            &accounts(),
            None,
            4096,
        )
        .unwrap();
        chain.register(&mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let (started, release) = operator.pause_next_close();
        operator.start_close(0).unwrap();
        started.recv().unwrap();
        operator
            .fence_suffix(0, "certified close invalidation".into())
            .unwrap();
        release.send(()).unwrap();
        for _ in 0..10_000 {
            operator.advance_close().unwrap();
            if operator.active_close.is_none() {
                break;
            }
            std::thread::yield_now();
            context.sleep(Duration::from_millis(1)).await;
        }
        let completed = operator.active_close.is_none();
        handle.abort();
        let _ = handle.await;
        let _ = operator.wait_for_closes();
        assert!(
            completed,
            "a canonically invalidated close must stop awaiting quorum"
        );
        assert!(matches!(
            operator.poll_close(0).unwrap(),
            Some(CloseEvent::Failed { .. })
        ));
    });
}

#[test]
fn virtual_first_credit_waits_for_admission_across_multiple_cutovers() {
    let database = TempDatabase::new();
    let recipient = Wallet::from_seed("Fresh", 91_001);
    let key = recipient.public_key();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let (send, entries) = operator.sign_send(0, &[(key.clone(), 25)]).unwrap();
    let first = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    rotate_epoch(&mut operator, 0);
    let (credit, credit_entries) = operator.sign_send(1, &[(key.clone(), 5)]).unwrap();
    operator.accept_send(credit, credit_entries).unwrap();
    rotate_epoch(&mut operator, 1);
    let empty = Endpoint {
        cumulative_debit: 0,
        seq: 0,
        entries: vec![],
    };
    let (spend, spend_entries) = sign_send_at(
        operator.registration.context.payment(),
        &recipient,
        &empty,
        &[(operator.wallets[2].public_key(), 7)],
    )
    .unwrap();
    assert!(
        operator
            .accept_send(spend.clone(), spend_entries.clone())
            .is_err()
    );
    assert!(
        operator
            .send_requires_epoch_registration(&spend, &spend_entries)
            .is_err()
    );

    let frozen = operator.store.epoch_reader().load(0).unwrap();
    let registration = registration_for(&operator.protocol, &frozen).unwrap();
    let prepared = operator.balances.prepare(frozen, registration).unwrap();
    let result = operator.balances.complete(prepared, 91).unwrap();
    assert_eq!(
        operator
            .balances
            .opening(1, &key)
            .unwrap()
            .verify::<Sha256>(&result.roots.successor)
            .unwrap()
            .get(),
        25
    );
    assert!(
        operator
            .accept_send(spend.clone(), spend_entries.clone())
            .is_err()
    );
    assert!(operator.payment_head(&key).is_err());
    assert_eq!(
        operator
            .accept_send(send.clone(), entries.clone())
            .unwrap()
            .into_accepted()
            .acceptance,
        first.acceptance
    );

    operator.record_admission(result).unwrap();
    operator.accept_send(spend, spend_entries).unwrap();
    assert_eq!(
        operator
            .store
            .current_account(&key)
            .unwrap()
            .unwrap()
            .current,
        23
    );
    assert_eq!(operator.store.current_liability().unwrap(), 400);
    drop(operator);

    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(operator.balances.startup_work().unwrap(), (vec![], vec![]));
    assert!(operator.payment_head(&key).is_err());
    operator.wait_for_closes().unwrap();
    assert_eq!(operator.payment_head(&key).unwrap().balance, 23);
    assert_eq!(operator.store.current_liability().unwrap(), 400);
    assert_eq!(
        operator
            .accept_send(send, entries)
            .unwrap()
            .into_accepted()
            .acceptance,
        first.acceptance
    );
    assert_eq!(operator.store.payer_endpoint(&key).unwrap().seq, 1);
}

#[test]
fn virtual_amount_reservation_and_incoming_credit_survive_restart() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let account = operator.wallets[0].public_key();
    operator.withdraw(0, amount(70)).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().balance, 30);
    assert_eq!(operator.store.current_liability().unwrap(), 330);
    let (send, entries) = operator.sign_send(1, &[(account.clone(), 20)]).unwrap();
    let accepted = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    assert_eq!(operator.payment_head(&account).unwrap().balance, 50);
    assert!(operator.pay(0, 2, 51).is_err());
    drop(operator);

    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(
        operator
            .accept_send(send, entries)
            .unwrap()
            .into_accepted()
            .acceptance,
        accepted.acceptance
    );
    assert_eq!(operator.payment_head(&account).unwrap().balance, 50);
    operator.pay(0, 2, 50).unwrap();
    let result = operator.complete_close(92).unwrap();
    assert_eq!(result.withdrawal_total, 70);
    assert_eq!(
        result.withdrawal_claims[0]
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        70
    );
    assert!(operator.store.current_account(&account).unwrap().is_none());
    assert_eq!(operator.store.current_liability().unwrap(), 330);
}

#[test]
fn virtual_credits_accumulate_before_one_owner_exit_and_recreate_afterward() {
    let mut operator = operator();
    let recipient = Wallet::from_seed("Accumulator", 91_002);
    let key = recipient.public_key();
    for (epoch, credit) in [20, 30, 40].into_iter().enumerate() {
        let (send, entries) = operator.sign_send(epoch, &[(key.clone(), credit)]).unwrap();
        operator.accept_send(send, entries).unwrap();
        let result = operator.complete_close(100 + epoch as u64).unwrap();
        assert_eq!(result.withdrawal_total, 0);
        assert!(result.withdrawal_claims.is_empty());
    }
    assert_eq!(operator.payment_head(&key).unwrap().balance, 90);
    let opening = operator.withdrawal_opening(&key).unwrap();
    let request = SignedWithdrawal::sign(
        operator.protocol.deployment(),
        opening.root.digest,
        Bytes::copy_from_slice(key.as_ref()),
        WithdrawalAction::Close,
        crate::protocol::epoch_start(3).unwrap() + 50,
        recipient.signer(),
    );
    operator.apply_withdrawal(request.clone()).unwrap();
    let closed = operator.complete_close(103).unwrap();
    assert_eq!(closed.withdrawal_total, 90);
    assert_eq!(closed.withdrawal_claims.len(), 1);
    assert!(operator.store.current_account(&key).unwrap().is_none());
    assert!(operator.balances.opening(4, &key).is_err());
    let (send, entries) = operator.sign_send(3, &[(key.clone(), 8)]).unwrap();
    operator.accept_send(send, entries).unwrap();
    assert!(operator.payment_head(&key).is_err());
    assert_eq!(operator.apply_withdrawal(request).unwrap().epoch, 3);
    let recreated = operator.complete_close(104).unwrap();
    assert_eq!(recreated.withdrawal_total, 0);
    assert!(recreated.withdrawal_claims.is_empty());
    assert_eq!(operator.payment_head(&key).unwrap().balance, 8);
    assert_eq!(operator.store.current_liability().unwrap(), 310);
    assert_eq!(
        operator
            .withdrawal_evidence(&key)
            .unwrap()
            .witness
            .batch_id(&closed.roots),
        closed.header.batch_id::<Sha256>()
    );
}

#[test]
fn virtual_first_credit_rejects_unadmitted_withdrawal() {
    let mut operator = operator();
    let recipient = Wallet::from_seed("Fresh withdrawal", 91_003);
    let key = recipient.public_key();
    assert!(operator.withdrawal_opening(&key).is_err());
    let (send, entries) = operator.sign_send(0, &[(key.clone(), 12)]).unwrap();
    operator.accept_send(send, entries).unwrap();
    assert!(operator.withdrawal_opening(&key).is_err());
    let frozen = operator.store.load_current().unwrap();
    let prepared = operator
        .balances
        .prepare(frozen, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, 0);
    let result = operator.balances.complete(prepared, 105).unwrap();
    let request = SignedWithdrawal::sign(
        operator.protocol.deployment(),
        result.roots.successor.digest,
        Bytes::copy_from_slice(key.as_ref()),
        WithdrawalAction::Close,
        crate::protocol::epoch_start(1).unwrap() + 50,
        recipient.signer(),
    );
    let changes = operator.store.total_changes();
    assert!(operator.withdrawal_opening(&key).is_err());
    assert!(operator.apply_withdrawal(request).is_err());
    assert_eq!(operator.store.total_changes(), changes);
    assert!(
        operator
            .store
            .load_current()
            .unwrap()
            .withdrawals
            .is_empty()
    );
}

#[test]
fn virtual_capacity_allows_new_recipients_beyond_the_genesis_account_bound() {
    let mut operator = operator();
    for payer in 0..4 {
        operator.deposit(payer, 200).unwrap();
    }
    let recipients = (0..1_021)
        .map(|index| Wallet::from_seed("Fresh", 100_000 + index).public_key())
        .collect::<Vec<_>>();
    for (payer, recipients) in recipients.chunks(crate::protocol::MAX_ENTRIES).enumerate() {
        let deltas = recipients
            .iter()
            .map(|key| (key.clone(), 1))
            .collect::<Vec<_>>();
        let (send, entries) = operator.sign_send(payer, &deltas).unwrap();
        operator.accept_send(send, entries).unwrap();
    }
    assert_eq!(operator.store.current_liability().unwrap(), 1_200);
    assert_eq!(operator.store.load_current().unwrap().accounts.len(), 1_025);
    let result = operator.complete_close(106).unwrap();
    assert_eq!(result.withdrawal_total, 0);
    assert_eq!(result.rows, 1_025);
    assert_eq!(operator.payment_head(&recipients[0]).unwrap().balance, 1);
}

#[test]
fn virtual_capacity_counts_deposits_and_payment_accounts_in_one_close() {
    let mut operator = operator();
    let deposits = (0..crate::protocol::MAX_DEPOSIT_EVENTS)
        .map(|index| DepositEvent {
            id: Sha256::hash(&[b"dynamic-capacity", &(index as u64).to_be_bytes()]),
            account: Wallet::from_seed("Depositor", 200_000 + index as u64).public_key(),
            amount: 1,
        })
        .collect::<Vec<_>>();
    operator.observe(&deposits).unwrap();
    let deltas = [
        (Wallet::from_seed("Fresh", 300_000).public_key(), 1),
        (Wallet::from_seed("Fresh", 300_001).public_key(), 1),
    ];
    let (send, entries) = operator.sign_send(0, &deltas).unwrap();
    operator.accept_send(send, entries).unwrap();
    let result = operator.complete_close(107).unwrap();
    assert_eq!(result.rows, crate::protocol::MAX_DEPOSIT_EVENTS + 3);
    assert_eq!(result.withdrawal_total, 0);
    assert_eq!(
        operator.store.current_liability().unwrap(),
        400 + crate::protocol::MAX_DEPOSIT_EVENTS as u64
    );
    let encoded = result.encode();
    assert_eq!(SettlementResult::decode(encoded).unwrap().rows, result.rows);
}

fn capacity_genesis(path: &Path) -> (Operator, Vec<Wallet>) {
    let wallets = (0..crate::protocol::MAX_GENESIS_ACCOUNTS)
        .map(|index| Wallet::from_seed("Owner", 400_000 + index as u64))
        .collect::<Vec<_>>();
    let identities = wallets
        .iter()
        .map(|wallet| AccountIdentity {
            name: wallet.name,
            key: wallet.public_key(),
        })
        .collect::<Vec<_>>();
    let accounts = identities
        .iter()
        .map(|identity| Account {
            key: identity.key.clone(),
            balance: 1,
        })
        .collect::<Vec<_>>();
    let operator = Operator::from_store(
        Store::open_configured(path, &identities, &accounts).unwrap(),
        identities,
        Protocol::new(NonZeroUsize::MIN).unwrap(),
        None,
        &accounts,
        None,
        4096,
    )
    .unwrap();
    (operator, wallets)
}

fn capacity_transfers(operator: &mut Operator, wallets: &[Wallet], recipients: usize) -> Vec<Key> {
    let recipients = (0..recipients)
        .map(|index| Wallet::from_seed("Fresh", 500_000 + index as u64).public_key())
        .collect::<Vec<_>>();
    let empty = Endpoint {
        cumulative_debit: 0,
        seq: 0,
        entries: vec![],
    };
    for (index, wallet) in wallets.iter().take(513).enumerate() {
        let (send, entries) = sign_send_at(
            operator.registration.context.payment(),
            wallet,
            &empty,
            &[(recipients[index % recipients.len()].clone(), 1)],
        )
        .unwrap();
        operator.accept_send(send, entries).unwrap();
    }
    recipients
}

#[test]
fn virtual_capacity_allows_more_activity_rows_without_more_live_accounts() {
    let (mut operator, wallets) = capacity_genesis(Path::new(":memory:"));
    let recipients = capacity_transfers(&mut operator, &wallets, 513);
    let result = operator.complete_close(108).unwrap();
    assert_eq!(result.rows, 1_026);
    assert_eq!(operator.store.load_current().unwrap().accounts.len(), 1_024);
    assert_eq!(operator.payment_head(&recipients[0]).unwrap().balance, 1);
    assert_eq!(
        SettlementResult::decode(result.encode()).unwrap().rows,
        1_026
    );
}

#[test]
fn virtual_capacity_replays_a_large_missing_checkpoint_once() {
    let database = TempDatabase::new();
    let (mut operator, wallets) = capacity_genesis(database.path());
    let recipients = capacity_transfers(&mut operator, &wallets, 512);
    operator.balances.fail_after_journal().unwrap();
    start_current_close(&mut operator).unwrap();
    let failed = operator
        .wait_for_closes()
        .err()
        .expect("injected crash completed");
    assert!(format!("{failed:#}").contains("injected"));
    drop(operator);

    let (mut operator, _) = capacity_genesis(database.path());
    assert_eq!(
        operator.balances.startup_work().unwrap(),
        (vec![1], vec![1])
    );
    operator.wait_for_closes().unwrap();
    assert_eq!(operator.store.load_current().unwrap().accounts.len(), 1_023);
    assert_eq!(operator.payment_head(&recipients[0]).unwrap().balance, 2);
    let result = operator.balances.stored_result(0).unwrap().unwrap();
    assert_eq!(result.rows, 1_025);
    assert_eq!(
        SettlementResult::decode(result.encode()).unwrap().rows,
        1_025
    );
    drop(operator);

    let (operator, _) = capacity_genesis(database.path());
    assert_eq!(operator.balances.startup_work().unwrap(), (vec![], vec![]));
    assert_eq!(operator.payment_head(&recipients[0]).unwrap().balance, 2);
}

#[test]
fn virtual_empty_bootstrap_deposits_and_receives_without_enrollment() {
    let database = TempDatabase::new();
    let open = || {
        Operator::from_store(
            Store::open_configured(database.path(), &[], &[]).unwrap(),
            vec![],
            Protocol::new(NonZeroUsize::MIN).unwrap(),
            None,
            &[],
            None,
            4096,
        )
        .unwrap()
    };
    let owner = Wallet::from_seed("Depositor", 600_000);
    let recipient = Wallet::from_seed("Fresh", 600_001).public_key();
    let mut operator = open();
    assert_eq!(operator.store.current_liability().unwrap(), 0);
    assert!(operator.store.load_current().unwrap().accounts.is_empty());
    operator
        .observe(&[DepositEvent {
            id: Sha256::hash(&[b"empty-bootstrap-deposit"]),
            account: owner.public_key(),
            amount: 2,
        }])
        .unwrap();
    operator.complete_close(109).unwrap();
    let empty = Endpoint {
        cumulative_debit: 0,
        seq: 0,
        entries: vec![],
    };
    let (send, entries) = sign_send_at(
        operator.registration.context.payment(),
        &owner,
        &empty,
        &[(recipient.clone(), 1)],
    )
    .unwrap();
    operator.accept_send(send, entries).unwrap();
    assert!(operator.payment_head(&recipient).is_err());
    operator.complete_close(110).unwrap();
    drop(operator);

    let operator = open();
    assert_eq!(operator.balances.startup_work().unwrap(), (vec![], vec![]));
    assert_eq!(operator.store.current_liability().unwrap(), 2);
    assert_eq!(
        operator.payment_head(&owner.public_key()).unwrap().balance,
        1
    );
    assert_eq!(operator.payment_head(&recipient).unwrap().balance, 1);
}
