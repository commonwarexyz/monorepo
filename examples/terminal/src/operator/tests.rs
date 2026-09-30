fn activity_range(
    operator: &Operator,
    epoch: u64,
) -> commonware_clearing::bajillion::transition::ActivityRange<Digest> {
    let result = operator.store.stored_result(epoch).unwrap().unwrap();
    result.roots.activity_range(&result.context).unwrap()
}

fn payout_claim(
    operator: &Operator,
    result: &SettlementResult,
    ordinal: u64,
) -> WithdrawalClaim<Digest> {
    operator
        .payout_proof(
            result.roots.withdrawal_outputs,
            result.context.predecessor_logs().payouts.operations + ordinal,
        )
        .unwrap()
}

use super::*;
use crate::{
    agent::{Agent, WithdrawalOutcome},
    chain::{
        client::{self, Chain as ChainBackend, Env},
        harness,
        ingress::Submission,
        light::Verified,
        node,
        query::{Lookup, ReadRequest},
        state::{
            AdmittedRootsResponse, DepositEffect, Record, RegistrationRecord, StatusRecord,
            WithdrawalResponse, admitted_key, deposit_key, intake_key, registration_key,
            status_key, withdrawal_key,
        },
        tx::{AdmitRequest, QueueWithdrawalRequest, SettlementTx, WithdrawalClaimRequest},
    },
    operator::rpc as operator_rpc,
    protocol::{INITIAL_BALANCE, deployment},
    rpc, service,
};
use commonware_clearing::bajillion::{
    qmdb::StateOpening,
    transition::{Header, WithdrawalClaim},
};
use commonware_cryptography::ed25519;
use commonware_p2p::utils::mocks::inert_channel;
use commonware_runtime::{
    Clock as _, Listener as _, Network as _, Runner as _, Spawner as _, Supervisor as _,
    deterministic,
};
use commonware_utils::{TestRng, sync::Mutex};
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
fn disabled_proof_replica_accepts_proposes_certifies_and_reopens_without_native_files() {
    let database = TempDatabase::new();
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let genesis = protocol.fixture_genesis(&accounts()).unwrap();
    let open = || {
        Operator::from_store(
            Store::open(database.path(), &identities()).unwrap(),
            identities(),
            Protocol::new(NonZeroUsize::MIN).unwrap(),
            None,
            &accounts(),
            Some(genesis),
            4096,
            false,
        )
        .unwrap()
    };
    let mut native_path = database.path().as_os_str().to_owned();
    native_path.push(".qmdb");
    let native_path = PathBuf::from(native_path);
    let mut operator = open();
    assert!(operator.balances.is_none());
    assert!(!native_path.exists());
    let (send, entries) = operator
        .sign_send(0, &[(operator.wallets[1].public_key(), 7)])
        .unwrap();
    let accepted = operator
        .accept_send(send.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    drop(operator);
    let mut operator = open();
    assert_eq!(
        operator
            .accept_send(send, entries)
            .unwrap()
            .into_accepted()
            .acceptance,
        accepted.acceptance
    );
    let prepared = operator
        .prepare_epoch(
            operator.store.load_current().unwrap(),
            operator.registration.clone(),
        )
        .unwrap();
    // A separate validator derives all three native commitments and returns its certificate.
    let derived = protocol
        .fixture_complete(&accounts(), &[], prepared.clone(), 811)
        .unwrap();
    let certified = crate::protocol::CertifiedEpoch {
        context: derived.context,
        header: derived.header,
        roots: derived.roots,
        withdrawal_total: derived.withdrawal_total,
        certificate: derived.certificate,
    };
    let result = prepared.certify(certified, 0, 0).unwrap();
    let successor = operator
        .protocol
        .registration(
            1,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            operator.store.successor_liability().unwrap(),
        )
        .unwrap();
    operator
        .store
        .rotate_epoch(
            0,
            operator.registration.context.payment(),
            &successor.context,
            &[],
            0,
        )
        .unwrap();
    operator
        .store
        .epoch_reader()
        .record_result(&result, operator.genesis.root())
        .unwrap();
    operator
        .store
        .finish_close(&result, operator.genesis.root())
        .unwrap();
    assert!(
        operator
            .payout_proof(result.roots.withdrawal_outputs, 0)
            .is_err()
    );
    assert!(!native_path.exists());
    drop(operator);
    let operator = open();
    assert!(operator.balances.is_none());
    assert_eq!(operator.registration.context.payment().epoch(), 1);
    assert_eq!(
        operator
            .store
            .current_account(&operator.wallets[0].public_key())
            .unwrap()
            .unwrap()
            .current,
        INITIAL_BALANCE - 7
    );
    assert!(
        operator
            .payment_head(&operator.wallets[0].public_key())
            .is_err()
    );
    assert!(!native_path.exists());
    drop(operator);
    fs::create_dir(&native_path).unwrap();
    fs::write(native_path.join("untouched"), b"not a native database").unwrap();
    let operator = open();
    assert!(operator.balances.is_none());
    assert_eq!(fs::read_dir(&native_path).unwrap().count(), 1);
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
        operator.store.predecessor(&recipient.public_key()).unwrap(),
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
            .as_ref()
            .unwrap()
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

    assert_eq!(operator.payment_head(&key).unwrap().balance, 25);
    let (send, entries) = sign_send_at(
        operator.registration.context.payment(),
        operator.store.predecessor(&recipient.public_key()).unwrap(),
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
        true,
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

/// Observation is idempotent by inbox index. A replay of observed entries
/// stages nothing, and after a restart a replay that extends past the durable
/// cursor stages only the new entries.
#[test]
fn observation_replay_is_idempotent_across_restart() {
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
    let third = DepositEvent {
        id: Sha256::hash(&[b"observed-batch-third"]),
        account: wallets()[2].public_key(),
        amount: 5,
    };

    // The first observation credits both entries at their indices.
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let staged = observe(&mut operator, 0, &[first.clone(), second.clone()]).unwrap();
    assert_eq!(
        staged
            .iter()
            .map(|event| (event.index, event.id))
            .collect::<Vec<_>>(),
        vec![(0, first.id), (1, second.id)]
    );
    assert_eq!(operator.observed().unwrap(), 2);
    let context = operator.registration.context.payment().clone();
    assert_eq!(
        operator.payment_head(&first.account).unwrap().balance,
        INITIAL_BALANCE + first.amount
    );
    assert_eq!(
        operator.payment_head(&second.account).unwrap().balance,
        INITIAL_BALANCE + second.amount
    );

    // A replay of both entries stages nothing.
    assert!(
        observe(&mut operator, 0, &[first.clone(), second.clone()])
            .unwrap()
            .is_empty()
    );
    assert_eq!(operator.registration.context.payment(), &context);
    drop(operator);

    // After a restart, a replay extending past the cursor stages only the new
    // entry.
    let mut recovered = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(recovered.observed().unwrap(), 2);
    assert_eq!(recovered.registration.context.payment(), &context);
    let staged = observe(&mut recovered, 1, &[second, third.clone()]).unwrap();
    assert_eq!(
        staged
            .iter()
            .map(|event| (event.index, event.id))
            .collect::<Vec<_>>(),
        vec![(2, third.id)]
    );
    assert_eq!(recovered.observed().unwrap(), 3);
    assert_eq!(recovered.store.load_current().unwrap().deposits.len(), 3);
    assert_eq!(
        recovered.payment_head(&first.account).unwrap().balance,
        INITIAL_BALANCE + first.amount
    );
}

/// An observation starting past the cursor would skip inbox entries, so it is
/// refused before any mutation.
#[test]
fn observation_gap_rejects_before_mutation() {
    let mut operator = operator();
    let event = DepositEvent {
        id: Sha256::hash(&[b"observed-batch-gap"]),
        account: wallets()[0].public_key(),
        amount: 7,
    };
    let before = operator.registration.context.payment().clone();
    let Err(error) = observe(&mut operator, 1, std::slice::from_ref(&event)) else {
        panic!("an observation past the cursor was recorded");
    };
    assert!(format!("{error:#}").contains("skips unobserved index 0"));
    operator.ensure_store_usable().unwrap();
    assert_eq!(operator.observed().unwrap(), 0);
    assert_eq!(operator.registration.context.payment(), &before);
    assert!(operator.store.load_current().unwrap().deposits.is_empty());
    assert_eq!(
        operator.payment_head(&event.account).unwrap().balance,
        INITIAL_BALANCE
    );
}

/// A fenced operator records certified intake but takes none of it, because
/// its live epoch never registers and settlement refunds the deposits.
#[test]
fn fenced_operator_records_intake_without_taking_it() {
    let mut operator = operator();
    let event = DepositEvent {
        id: Sha256::hash(&[b"fenced-intake"]),
        account: wallets()[0].public_key(),
        amount: 7,
    };

    // A certified fault fences the operator.
    operator
        .fence_suffix(0, "certified deployment fault".to_string())
        .unwrap();

    // Observation advances the cursor and leaves the deposit untaken and uncredited.
    assert!(
        observe(&mut operator, 0, std::slice::from_ref(&event))
            .unwrap()
            .is_empty()
    );
    assert_eq!(operator.observed().unwrap(), 1);
    assert_eq!(
        operator.store.untaken().unwrap(),
        [(0, Intake::Deposit(event.clone()))]
    );
    assert!(operator.store.load_current().unwrap().deposits.is_empty());
    assert_eq!(
        operator
            .store
            .current_account(&event.account)
            .unwrap()
            .unwrap()
            .current,
        INITIAL_BALANCE
    );
}

/// Intake never fails for capacity. The live boundary takes the inbox up to
/// its deposit limit, and the suffix waits for the successor, which takes it
/// at the cutover. Fresh extras wait while the suffix does, so they never take
/// capacity the inbox needs.
#[test]
fn capacity_leaves_the_suffix_for_the_next_epoch() {
    let mut operator = operator();
    let wallet = wallets().remove(0);
    let account = wallet.public_key();
    let opening = operator.withdrawal_opening(&account).unwrap();
    let extra = SignedWithdrawal::sign(
        deployment(),
        opening.root.digest,
        account.encode(),
        amount(5),
        100,
        wallet.signer(),
    );
    let limit = crate::protocol::MAX_DEPOSIT_EVENTS as u64;
    let deposits = (0..=limit)
        .map(|index| DepositEvent {
            id: Sha256::hash(&[b"capacity-suffix", &index.to_be_bytes()]),
            account: Wallet::from_seed("Depositor", 400_000 + index).public_key(),
            amount: 1,
        })
        .collect::<Vec<_>>();
    let last = deposits.last().unwrap().clone();

    // One observation takes the inbox up to the limit, leaves the last deposit
    // untaken, and the boundary publishes over the taken prefix.
    let staged = observe(&mut operator, 0, &deposits).unwrap();
    assert_eq!(staged.len(), crate::protocol::MAX_DEPOSIT_EVENTS);
    assert_eq!(operator.observed().unwrap(), limit + 1);
    assert_eq!(operator.registration.intake, 0..limit);
    assert_eq!(
        operator.store.untaken().unwrap(),
        [(limit, Intake::Deposit(last.clone()))]
    );

    // A fresh extra waits while the suffix does.
    let Err(error) = operator.apply_withdrawal(extra.clone(), false) else {
        panic!("a fresh extra took capacity ahead of an untaken inbox row");
    };
    assert!(format!("{error:#}").contains("leaves inbox rows untaken"));
    assert!(operator.staged_withdrawal(&extra).unwrap().is_none());
    assert_eq!(operator.signed_registration().unwrap().end, limit);

    // The cutover's successor takes the suffix, and the extra then stages.
    operator.complete_close(108).unwrap();
    assert_eq!(operator.registration.intake, limit..limit + 1);
    assert!(operator.store.untaken().unwrap().is_empty());
    assert_eq!(operator.store.load_current().unwrap().deposits, [last]);
    assert_eq!(operator.apply_withdrawal(extra, false).unwrap().epoch, 1);
}

/// A chain-queued withdrawal observed for an account whose fresh extra sits in
/// the unpublished live boundary supersedes the extra. Settlement would reject
/// a boundary carrying both, so the take discards the extra and restores its
/// reservation before it stages the queued request.
#[test]
fn superseding_queued_withdrawal_discards_the_extra() {
    let mut operator = operator();
    let wallet = wallets().remove(0);
    let account = wallet.public_key();
    let opening = operator.withdrawal_opening(&account).unwrap();
    let sign = |action, deadline| {
        SignedWithdrawal::sign(
            deployment(),
            opening.root.digest,
            account.encode(),
            action,
            deadline,
            wallet.signer(),
        )
    };

    // The operator stages a fresh extra for the account.
    let extra = sign(amount(5), 100);
    operator.apply_withdrawal(extra.clone(), false).unwrap();
    assert_eq!(
        operator
            .store
            .current_account(&account)
            .unwrap()
            .unwrap()
            .current,
        INITIAL_BALANCE - 5
    );

    // The chain queues a different request for the account, and the live
    // boundary takes it in place of the extra.
    let queued = sign(amount(3), 101);
    assert!(
        operator
            .observe(0, &[Intake::Withdrawal(queued.clone())])
            .unwrap()
            .is_empty()
    );
    assert!(
        operator
            .store
            .staged_withdrawal_request(&extra)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        operator.staged_withdrawal(&queued).unwrap().unwrap().epoch,
        0
    );
    assert_eq!(
        operator.registration.withdrawals.requests(),
        std::slice::from_ref(&queued)
    );
    assert_eq!(operator.registration.intake, 0..1);
    assert!(operator.store.untaken().unwrap().is_empty());
    assert_eq!(
        operator
            .store
            .current_account(&account)
            .unwrap()
            .unwrap()
            .current,
        INITIAL_BALANCE - 3
    );
    assert_eq!(
        operator
            .signed_registration()
            .unwrap()
            .withdrawals
            .requests(),
        std::slice::from_ref(&queued)
    );
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
                .as_ref()
                .unwrap()
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
            operator.apply_withdrawal(request, false).is_err(),
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
                .as_ref()
                .unwrap()
                .root(operator.registration.context.payment().epoch())
                .unwrap()
                .digest,
            destination.encode(),
            amount(3),
            50,
            wallet.signer(),
        );
        let applied = operator.apply_withdrawal(request.clone(), false).unwrap();
        assert_eq!(applied.action, amount(3));
        assert_eq!(
            operator.apply_withdrawal(request, false).unwrap().epoch,
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
                true,
            )
            .unwrap();
            assert_eq!(
                operator.store.current_liability().unwrap(),
                balances.into_iter().sum::<u64>()
            );
            assert_eq!(
                operator
                    .balances
                    .as_ref()
                    .unwrap()
                    .root(operator.registration.context.payment().epoch())
                    .unwrap(),
                operator.genesis.root()
            );
            for (identity, balance) in identities.iter().zip(balances) {
                if balance == 0 {
                    assert!(operator.payment_head(&identity.key).is_err());
                    continue;
                }
                let head = operator.payment_head(&identity.key).unwrap();
                assert_eq!(head.balance, balance);
                let opening = operator
                    .balances
                    .as_ref()
                    .unwrap()
                    .opening(0, &identity.key)
                    .unwrap();
                assert_eq!(
                    opening
                        .verify::<Sha256>(&operator.genesis.root())
                        .unwrap()
                        .get(),
                    balance
                );
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
        true,
    )
    .unwrap();
    let account = identities[0].key.clone();
    let empty = operator.genesis.root();
    observe(
        &mut operator,
        0,
        &[DepositEvent {
            id: Sha256::hash(&[b"first-positive-balance"]),
            account: account.clone(),
            amount: 20,
        }],
    )
    .unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 20);
    assert!(operator.payment_head(&account).is_err());
    assert_eq!(operator.balances.as_ref().unwrap().root(0).unwrap(), empty);
    let result = operator.complete_close(17).unwrap();
    assert_eq!(operator.payment_head(&account).unwrap().balance, 20);
    assert_eq!(
        operator
            .balances
            .as_ref()
            .unwrap()
            .opening(1, &account)
            .unwrap()
            .verify::<Sha256>(&result.roots.successor)
            .unwrap()
            .get(),
        20
    );
    assert!(
        operator
            .balances
            .as_ref()
            .unwrap()
            .opening(0, &account)
            .is_err()
    );
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
        true,
    )
    .unwrap();

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
            true,
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
            .as_ref()
            .unwrap()
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
            true,
        )
        .unwrap();
        assert_eq!(operator.store.current_liability().unwrap(), 14);
        for identity in &identities {
            let head = operator.payment_head(&identity.key).unwrap();
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
    fn holders(&self) -> Result<Vec<SocketAddr>> {
        self.client.holders()
    }

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

    async fn inbox<E: Env>(
        &mut self,
        ctx: &E,
        indices: std::ops::Range<u64>,
    ) -> Result<Vec<crate::chain::state::Intake>> {
        client::inbox(ctx, self, indices).await
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
                    .prepare_epoch(
                        operator.store.load_current().unwrap(),
                        operator.registration.clone(),
                    )
                    .unwrap();
                rotate_epoch(&mut operator, 0);
                saved = operator.complete_prepared(prepared, 0).unwrap().encode();
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
                true,
            )
            .unwrap();

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
                        recovered.store.stored_result(0).unwrap().unwrap().encode(),
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
                recovered.store.stored_result(0).unwrap().unwrap().encode(),
                saved
            );

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
        .prepare_epoch(
            operator.store.load_current().unwrap(),
            operator.registration.clone(),
        )
        .unwrap();
    rotate_epoch(operator, epoch);
    let result = operator.complete_prepared(prepared, epoch).unwrap();
    let record = AdmittedRootsResponse {
        batch_id: result.header.batch_id::<Sha256>(),
        roots: result.roots,
        activity_start: result.context.predecessor_logs().activity.operations,
        finalized: false,
    };
    operator.record_admission(&result).unwrap();
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
    let staged = observe(&mut recovered, 0, std::slice::from_ref(&event)).unwrap();
    assert_eq!(staged.len(), 1);
    assert!(recovered.pay(0, 1, 1).is_err());
    recovered.wait_for_closes().unwrap();
    release(&mut recovered);
    assert!(observe(&mut recovered, 0, &[event]).unwrap().is_empty());
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
        true,
    )
    .unwrap();

    while recovered.active_close.is_some() {
        recovered.advance_close().unwrap();
        std::thread::yield_now();
        context.sleep(Duration::from_millis(1)).await;
    }
    release(&mut recovered);
    recovered
}

/// A chain on which no admission ever becomes visible.
struct Unadmitted;

impl ChainBackend for Unadmitted {
    fn holders(&self) -> Result<Vec<SocketAddr>> {
        anyhow::bail!("admission-only fixture has no evidence holders")
    }

    fn deployment(&self) -> Digest {
        deployment()
    }

    async fn read<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        let mut empty = PendingAdmission {
            records: BTreeMap::new(),
        };
        empty.read(ctx, request).await
    }

    async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        self.read(ctx, request).await
    }

    async fn inbox<E: Env>(
        &mut self,
        ctx: &E,
        indices: std::ops::Range<u64>,
    ) -> Result<Vec<crate::chain::state::Intake>> {
        client::inbox(ctx, self, indices).await
    }

    async fn submit<E: Env>(&mut self, _: &E, tx: &SettlementTx) -> Result<Submission> {
        assert!(matches!(tx, SettlementTx::Admit(_)));
        Ok(Submission::Accepted)
    }
}

/// Reopens the operator over a close pipeline that never completes: its
/// committee never votes and its chain never shows an admission, so a close
/// pending at the restart stays held.
fn reopen_held(context: &deterministic::Context, path: &Path) -> Operator {
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let (certifier, mailbox) = node::Certifier::new(
        context.child("certifier"),
        node::Config {
            verifier: protocol.verifier(),
            chain: Unadmitted,
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
    Operator::from_store(
        store,
        identities,
        protocol,
        Some(pipeline),
        &accounts(),
        None,
        4096,
        true,
    )
    .unwrap()
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
        assert!(recovered.store.stored_result(0).unwrap().is_some());
    });
}

#[test]
fn unfinalized_closes_allow_successor_batches_and_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        let recipients = [
            (operator.wallets[1].public_key(), 1),
            (operator.wallets[2].public_key(), 1),
        ];
        let mut records = BTreeMap::new();

        // Admission advances the spendable head while every earlier close remains
        // challengeable. Repeated batches in each successor use that head immediately.
        for epoch in 0..8 {
            assert_eq!(operator.signed_registration().unwrap().epoch, epoch);
            for _ in 0..2 {
                let (send, entries) = operator.sign_send(0, &recipients).unwrap();
                let accepted = operator.accept_send(send, entries).unwrap().into_accepted();
                assert_eq!(accepted.epoch, epoch);
                assert_eq!(accepted.total, 2);
                assert_eq!(accepted.acceptance.entries.len(), 2);
            }
            assert_eq!(operator.automatic_epoch().unwrap(), Some(epoch));
            operator.validate_close_start(epoch).unwrap();
            records.insert(epoch, admit_pending(&mut operator));
        }
        assert_eq!(operator.pending_epochs().unwrap().len(), 8);
        assert!(operator.store.latest_finalized_root().unwrap().is_none());
        drop(operator);

        // Restart authenticates the retained admissions without requiring finality.
        // Their evidence survives until the ordinary finalization observations arrive.
        let mut operator = reopen_admitted(&context, database.path(), records.clone()).await;
        assert_eq!(operator.signed_registration().unwrap().epoch, 8);
        let (send, entries) = operator.sign_send(0, &recipients).unwrap();
        assert_eq!(
            operator
                .accept_send(send, entries)
                .unwrap()
                .into_accepted()
                .total,
            2
        );
        assert_eq!(operator.pending_epochs().unwrap().len(), 8);
        assert_eq!(
            operator
                .payment_head(&operator.wallets[0].public_key())
                .unwrap()
                .balance,
            INITIAL_BALANCE - 34
        );
        for (epoch, mut record) in records {
            record.finalized = true;
            operator.observe_admitted(epoch, &record).unwrap();
        }
        assert!(operator.pending_epochs().unwrap().is_empty());
        assert!(operator.store.stored_result(0).unwrap().is_some());
    });
}

#[test]
fn wallet_withdrawal_uses_finalized_root_across_pending_closes() {
    for (action, queued) in [
        (amount(25), false),
        (WithdrawalAction::Close, false),
        (amount(25), true),
        (WithdrawalAction::Close, true),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let timing = Timing {
                admission_offset: 100,
                challenge_duration: 100,
            };
            let address = SocketAddr::from(([127, 0, 0, 1], 9_800));
            let chain = Chain {
                control: harness::start_with_native(
                    &context,
                    address,
                    "chain",
                    harness::native(crate::protocol::deployments()),
                    timing,
                )
                .await,
            };
            let mut client = client::Client::new(
                chain.control.identity(),
                deployment(),
                vec![address],
                context.child("client_rng"),
            )
            .unwrap();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            for epoch in 0..6 {
                chain.register(&mut operator).await;
                operator.pay(1, 2, 1).unwrap();
                let pending = admit_pending(&mut operator);
                let result = operator.store.stored_result(epoch).unwrap().unwrap();
                chain.control.submit(SettlementTx::Admit(AdmitRequest::from(&result))).await;
                assert_eq!(client.admitted(&context, epoch).await.unwrap(), Some(pending));
            }
            let finalized = chain.status().await;
            assert!(finalized.last_finalized.is_none());
            assert!(operator.store.latest_finalized_root().unwrap().is_none());
            assert_eq!(operator.pending_epochs().unwrap(), [0, 1, 2, 3, 4, 5]);
            assert_ne!(operator.balances.as_ref().unwrap().root(6).unwrap(), finalized.state_root);
            let bystander = wallets()[1].public_key();
            let opening = operator.withdrawal_opening(&bystander).unwrap();
            assert_eq!(opening.root, finalized.state_root);
            assert_eq!(opening.opening.account, bystander);
            assert_eq!(opening.opening.verify::<Sha256>(&opening.root).unwrap().get(), INITIAL_BALANCE);
            let account = wallets()[0].public_key();
            let native_before = client.native_balance(&context, chain.control.identity().native.chain_id(), account.clone()).await.unwrap();

            let wrong = SignedWithdrawal::sign(
                deployment(),
                operator.balances.as_ref().unwrap().root(6).unwrap().digest,
                account.encode(),
                action,
                finalized.height + crate::protocol::settlement_config(&timing).unwrap().maximum_withdrawal_notice.get(),
                wallets()[0].signer(),
            );
            let operator = Mutex::new(operator);
            let error = service::prepare_request(
                &context,
                &mut client,
                &operator,
                &operator_rpc::OperatorRequest::ApplyWithdrawal(operator_rpc::ApplyWithdrawalRequest { request: wrong.clone() }),
                timing,
            ).await.unwrap_err();
            assert!(format!("{error:#}").contains("current finalized state"));
            assert!(operator.lock().staged_withdrawal(&wrong).unwrap().is_none());
            assert!(operator.lock().store.load_current().unwrap().withdrawals.is_empty());
            let mut operator = operator.into_inner();

            let unavailable = SocketAddr::from(([127, 0, 0, 1], 9_802));
            let mut agent = Agent::open(database.path(), 0).unwrap();
            if queued {
                let WithdrawalOutcome::Signed { request, .. } = agent.withdraw(&context, &mut client, unavailable, action).await.unwrap() else {
                    panic!("unavailable operator acknowledged withdrawal");
                };
                assert_eq!(agent.escalate_withdrawal(&context, &mut client).await.unwrap(), request);
                let deadline = operator.store.stored_result(5).unwrap().unwrap().context.challenge_deadline();
                let height = chain.control.advance(0).await;
                chain.control.advance(deadline.saturating_sub(height) + 1).await;
                let observing = Mutex::new(operator);
                service::observe_closes(&context, &mut client, &observing).await.unwrap();
                operator = observing.into_inner();
                assert!(operator.pending_epochs().unwrap().is_empty());
                let current = chain.status().await;
                assert_eq!(current.last_finalized, Some(5));
                assert_ne!(request.body().state_root(), &current.state_root.digest);
                assert!(current.height < request.body().deadline());
                assert!(request.body().deadline() < current.height + crate::protocol::settlement_config(&timing).unwrap().minimum_withdrawal_notice.get());
                assert_eq!(client.withdrawal(&context, account.clone()).await.unwrap(), Some(request));
                let opening = operator.withdrawal_opening(&bystander).unwrap();
                assert_eq!(opening.root, operator.balances.as_ref().unwrap().root(6).unwrap());
                assert_eq!(opening.root, current.state_root);
                assert_eq!(opening.opening.account, bystander);
                assert_eq!(opening.opening.verify::<Sha256>(&opening.root).unwrap().get(), INITIAL_BALANCE - 6);
            }

            let mut listener = context.bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
            let operator_address = listener.local_addr().unwrap();
            let mut serving_chain = client::Client::new(
                chain.control.identity(),
                deployment(),
                vec![address],
                context.child("serving_rng"),
            )
            .unwrap();
            let server = context.child("withdrawal_dispatch").spawn(move |context| async move {
                let operator = Mutex::new(operator);
                let mut expected = None;
                let mut applies = 0;
                while applies < 3 {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let request = operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap()).unwrap();
                    if matches!(&request, operator_rpc::OperatorRequest::WithdrawalOpening(_)) {
                        let response = operator_rpc::handle_decoded(&mut operator.lock(), request);
                        rpc::send_response(&mut sink, &response).await.unwrap();
                        continue;
                    }
                    let operator_rpc::OperatorRequest::ApplyWithdrawal(body) = &request else {
                        panic!("unexpected withdrawal request");
                    };
                    assert_eq!(body.request.body().state_root(), &finalized.state_root.digest);
                    match &expected {
                        Some(expected) => assert_eq!(&body.request, expected),
                        None => expected = Some(body.request.clone()),
                    }
                    applies += 1;
                    let prepared = service::prepare_request(&context, &mut serving_chain, &operator, &request, timing).await.unwrap();
                    let response = prepared.unwrap_or_else(|| operator_rpc::handle_decoded(&mut operator.lock(), request));
                    if applies != 2 {
                        rpc::send_response(&mut sink, &response).await.unwrap();
                    }
                }
                operator.into_inner()
            });

            let outcome = agent.withdraw(&context, &mut client, operator_address, action).await.unwrap();
            let WithdrawalOutcome::Applied { epoch, request } = outcome else {
                panic!("withdrawal against the finalized root must be carried: {outcome:?}");
            };
            assert_eq!(epoch, 6);
            drop(agent);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(matches!(agent.withdraw(&context, &mut client, operator_address, action).await.unwrap(),
                WithdrawalOutcome::Signed { request: ref retained, .. } if retained == &request));
            drop(agent);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(matches!(agent.withdraw(&context, &mut client, operator_address, action).await.unwrap(),
                WithdrawalOutcome::Applied { epoch: 6, request: ref retained } if retained == &request));
            let mut operator = server.await.unwrap();
            chain.register(&mut operator).await;
            admit_pending(&mut operator);
            let result = operator.store.stored_result(6).unwrap().unwrap();
            chain.admit(&result).await;
            let observing = Mutex::new(operator);
                service::observe_closes(&context, &mut client, &observing).await.unwrap();
                operator = observing.into_inner();
                assert!(operator.pending_epochs().unwrap().is_empty());
            let opening = operator.withdrawal_opening(&bystander).unwrap();
            assert_eq!(opening.root, operator.balances.as_ref().unwrap().root(7).unwrap());
            assert_eq!(opening.root, chain.status().await.state_root);
            assert_eq!(opening.opening.account, bystander);
            assert_eq!(opening.opening.verify::<Sha256>(&opening.root).unwrap().get(), INITIAL_BALANCE - 6);
            let release = agent.claim_withdrawal(&context, &mut client, unavailable).await.unwrap();
            let expected = match action {
                WithdrawalAction::Amount(amount) => amount.get(),
                WithdrawalAction::Close => INITIAL_BALANCE,
            };
            assert_eq!(release.amount, expected);
            assert_eq!(client.native_balance(&context, chain.control.identity().native.chain_id(), account.clone()).await.unwrap(), native_before + expected);
            drop(agent);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(agent.claim_withdrawal(&context, &mut client, unavailable).await.is_err());
            assert_eq!(client.native_balance(&context, chain.control.identity().native.chain_id(), account).await.unwrap(), native_before + expected);
        });
    }
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
    assert_eq!(start_current_close(&mut operator).unwrap().epoch, 1);
    started.recv().unwrap();
    operator
        .fence_suffix(0, "certified challenge of epoch 0".to_string())
        .unwrap();
    release.send(()).unwrap();
    let events = operator.wait_for_closes().unwrap();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|event| matches!(event, CloseEvent::Failed { epoch: 1, .. }))
    );
    assert!(operator.store.stored_result(1).unwrap().is_none());
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
fn restarted_observer_finishes_the_retired_certified_prefix_once() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let address = SocketAddr::from(([127, 0, 0, 1], 9_800));
        let chain = Chain {
            control: harness::start_with_native(
                &context,
                address,
                "chain",
                harness::native(crate::protocol::deployments()),
                Timing {
                    admission_offset: 10,
                    challenge_duration: 20,
                },
            )
            .await,
        };
        let client = |label| {
            client::Client::new(
                chain.control.identity(),
                deployment(),
                vec![address],
                context.child(label),
            )
            .unwrap()
        };
        let mut serving = client("serving");
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        let mut deadline = 0;
        for epoch in 0..3 {
            chain.register(&mut operator).await;
            operator.pay(1, 2, 1).unwrap();
            admit_pending(&mut operator);
            let result = operator.store.stored_result(epoch).unwrap().unwrap();
            deadline = result.context.challenge_deadline();
            chain
                .control
                .submit(SettlementTx::Admit(AdmitRequest::from(&result)))
                .await;
        }
        assert_eq!(operator.pending_epochs().unwrap(), [0, 1, 2]);
        assert!(operator.store.latest_finalized_root().unwrap().is_none());
        let height = chain.control.advance(0).await;
        chain
            .control
            .advance(deadline.saturating_sub(height) + 1)
            .await;
        assert_eq!(
            serving.payout_checkpoint(&context).await.unwrap().finalized,
            Some(2)
        );
        assert!(serving.admitted(&context, 0).await.is_err());
        let first = operator.store.stored_result(0).unwrap().unwrap();
        let next = operator.store.stored_result(1).unwrap().unwrap();
        let committee = crate::protocol::committee().unwrap();
        let verifier =
            commonware_clearing::bajillion::admission::bls12381::Scheme::verifier(committee);
        for signer_count in 2..=4 {
            let mut request = AdmitRequest::from(&first);
            request.certificate =
                crate::protocol::fixture_certificate(&request.header, signer_count);
            assert!(verifier.verify(&request.header, &request.certificate));
            assert_eq!(
                crate::protocol::has_consensus_quorum(&request.certificate),
                signer_count >= 3
            );
            let result = client::admit(&context, &mut serving, &first.context, request).await;
            if signer_count == 2 {
                assert!(
                    result.is_err(),
                    "retired admission accepted a sub-consensus certificate"
                );
            } else {
                result.unwrap();
            }
        }
        for mutation in 0..5 {
            let mut request = AdmitRequest::from(&first);
            match mutation {
                0 => request.deployment = Sha256::hash(&[b"foreign retired deployment"]),
                1 => request.epoch = 1,
                2 => request.roots = next.roots,
                3 => request.header = next.header,
                4 => request.certificate = next.certificate.clone(),
                _ => unreachable!(),
            }
            assert!(
                client::admit(&context, &mut serving, &first.context, request)
                    .await
                    .is_err(),
                "finalization accepted an unbound close mutation {mutation}"
            );
        }
        assert!(
            client::admit(
                &context,
                &mut serving,
                &next.context,
                AdmitRequest::from(&first),
            )
            .await
            .is_err()
        );
        let mut encoded = first.context.encode().to_vec();
        encoded[0] ^= 1;
        let inconsistent =
            commonware_clearing::bajillion::transition::CloseContext::decode(encoded).unwrap();
        assert!(!inconsistent.epoch_context().verify_anchor::<Sha256>());
        let mut request = AdmitRequest::from(&first);
        request.header =
            Header::new::<Sha256, _>(&inconsistent, &request.roots, request.withdrawal_total);
        request.certificate = crate::protocol::fixture_certificate(&request.header, 3);
        assert!(crate::protocol::has_consensus_quorum(&request.certificate));
        assert!(verifier.verify(&request.header, &request.certificate));
        assert!(
            client::admit(&context, &mut serving, &inconsistent, request)
                .await
                .is_err(),
            "a certificate must not bypass the context's internal anchor validation"
        );
        drop(operator);

        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let (certifier, mailbox) = node::Certifier::new(
            context.child("admission"),
            node::Config {
                verifier: protocol.verifier(),
                chain: client("admission_client"),
                mailbox_size: NonZeroUsize::new(10).unwrap(),
            },
        );
        let peers = (0..crate::protocol::committee().unwrap().members().len())
            .map(|index| ed25519::PrivateKey::from_seed(index as u64).public_key())
            .collect::<Vec<_>>();
        certifier.start(inert_channel(peers.clone()));
        let pipeline = node::Pipeline::new(mailbox, &peers, deployment()).unwrap();
        for _ in 0..2 {
            let operator = Mutex::new(
                Operator::from_store(
                    Store::open(database.path(), &identities()).unwrap(),
                    identities(),
                    Protocol::new(NonZeroUsize::MIN).unwrap(),
                    Some(pipeline.clone()),
                    &accounts(),
                    None,
                    4096,
                    false,
                )
                .unwrap(),
            );
            for _ in 0..2_000 {
                service::observe_closes(&context, &mut serving, &operator)
                    .await
                    .unwrap();
                if operator.lock().pending_epochs().unwrap().is_empty() {
                    break;
                }
                std::thread::yield_now();
                context.sleep(Duration::from_millis(1)).await;
            }
            let mut operator = operator.lock();
            assert!(
                operator.pending_epochs().unwrap().is_empty(),
                "certified jobs behind the retired prefix did not finish"
            );
            for epoch in 0..3 {
                assert!(matches!(
                    operator.poll_close(epoch).unwrap(),
                    Some(CloseEvent::Finished(_))
                ));
            }
            assert_eq!(
                operator.store.latest_finalized_root().unwrap().unwrap().0,
                2
            );
            assert_eq!(
                operator
                    .store
                    .current_account(&operator.wallets[1].public_key())
                    .unwrap()
                    .unwrap()
                    .current,
                INITIAL_BALANCE - 3
            );
        }
    });
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
                let close = operator.store.stored_result(epoch).unwrap().unwrap();
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
                let (deadline, _) = client
                    .registration(&context)
                    .await
                    .unwrap()
                    .unwrap()
                    .deadlines
                    .unwrap();
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
                            commitment::empty_root::<Sha256>(VectorKind::OutEntry),
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
    operator.fail_next_result_read();
    let (started, release) = operator.pause_next_close();
    assert_eq!(start_current_close(&mut operator).unwrap().epoch, 1);
    started.recv().unwrap();
    operator
        .fence_suffix(0, "certified ancestor challenge".into())
        .unwrap();
    release.send(()).unwrap();
    assert!(operator.wait_for_closes().is_err());
    assert!(
        operator.ensure_store_usable().is_err(),
        "a durable fault must not hide a failed close-result store"
    );
}

/// Adopts the live epoch's registration as a chain would certify it at
/// `registered`, with the deadlines of an epoch that became the frontier then.
fn adopt_at(operator: &mut Operator, registered: u64, timing: Timing) -> RegistrationRecord {
    let admission = registered + timing.admission_offset;
    operator
        .adopt_at(
            registered,
            Some((admission, admission + timing.challenge_duration)),
        )
        .unwrap()
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
            let record = adopt_at(&mut operator, 10, timing);
            assert_eq!(operator.automatic_epoch().unwrap(), Some(0));
            operator.pay(0, 1, 1).unwrap();
            let due = (10 + 4).min(10 + offset - offset.min(4));
            assert!(
                operator
                    .close_if_due(&record, due - 1, timing)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                operator
                    .close_if_due(&record, due, timing)
                    .unwrap()
                    .unwrap()
                    .epoch,
                0
            );
            operator.pay(1, 2, 1).unwrap();
            assert!(
                operator
                    .close_if_due(&record, due + 100, timing)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(operator.status().unwrap().epoch, 1);
            operator.wait_for_closes().unwrap();
        }
    });
}

#[test]
fn automatic_cut_releases_capacity() {
    deterministic::Runner::default().start(|_| async move {
        let mut operator = operator();
        for _ in 0..MAX_DEPOSIT_EVENTS {
            operator.deposit(0, 1).unwrap();
        }
        let timing = Timing {
            admission_offset: 30,
            challenge_duration: 8,
        };
        let record = adopt_at(&mut operator, 10, timing);
        assert!(
            operator
                .close_if_due(&record, 10, timing)
                .unwrap()
                .is_some()
        );
        operator.wait_for_closes().unwrap();
        assert_eq!(operator.pay(0, 1, 1).unwrap().epoch, 1);
    });
}

impl ChainBackend for PendingAdmission {
    fn holders(&self) -> Result<Vec<SocketAddr>> {
        anyhow::bail!("admission-only fixture has no evidence holders")
    }

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
            claimed: None,
            payout_tip: request
                .lookup
                .requires_payout_tip()
                .then(|| crate::protocol::PayoutTip {
                    payouts: commonware_clearing::bajillion::logs::Heads::empty::<
                        crate::protocol::Key,
                        Sha256,
                    >()
                    .payouts,
                    finalized: None,
                }),
            height: 1,
            timestamp: 0,
            record,
        })
    }

    async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        self.read(ctx, request).await
    }

    async fn inbox<E: Env>(
        &mut self,
        ctx: &E,
        indices: std::ops::Range<u64>,
    ) -> Result<Vec<crate::chain::state::Intake>> {
        client::inbox(ctx, self, indices).await
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
            records: [(result.context.payment().epoch(), AdmittedRootsResponse::new(result.header.batch_id::<Sha256>(), result.roots, result.context.predecessor_logs().activity.operations, false))].into(),
        };
        commonware_macros::select! {
            outcome = client::admit(&context, &mut chain, &result.context, AdmitRequest::from(&result)) => outcome.unwrap(),
            _ = context.sleep(Duration::from_secs(1)) => panic!("certified admission waited for clearing finalization"),
        }
        assert!(!chain.records[&result.context.payment().epoch()].finalized);
    });
}

/// Unwraps an output verified as consumed in the current harness snapshot.
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

    async fn deposit(&self, event: DepositEvent) -> DepositEffect {
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
        match self
            .control
            .record(deposit_key(&deployment(), &event.id))
            .await
        {
            Some(Record::Deposit(recorded)) if recorded.event == event => recorded,
            record => panic!("expected the deposit record, found {record:?}"),
        }
    }

    async fn queue_withdrawal(
        &self,
        request: SignedWithdrawal<Key, Digest>,
        opening: StateOpening<Key, Digest>,
    ) {
        let account = request.account().clone();
        self.control
            .submit(SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: request.clone(),
                opening,
            }))
            .await;
        assert!(matches!(
            self.control.record(withdrawal_key(&deployment(), &account)).await,
            Some(Record::Withdrawal(recorded)) if recorded.request == request
        ));
    }

    /// Records the certified inbox entries the operator has not observed, as
    /// the service's observation does, and returns the newly credited deposits.
    async fn observe(&self, operator: &mut Operator) -> Vec<StagedDeposit> {
        let start = operator.observed().unwrap();
        let mut records = Vec::new();
        for index in start..self.status().await.intake {
            match self.control.record(intake_key(&deployment(), index)).await {
                Some(Record::Intake(record)) => records.push(record),
                record => panic!("expected inbox entry {index}, found {record:?}"),
            }
        }
        operator.observe(start, &records).unwrap()
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
        match self
            .control
            .record(registration_key(&deployment(), epoch))
            .await
        {
            Some(Record::Registration(record)) => Some(record),
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

    /// Authenticates a restarted operator's live epoch against the chain.
    async fn release(&self, operator: &mut Operator) {
        let epoch = operator.registration.context.payment().epoch();
        let record = match self
            .control
            .record(registration_key(&deployment(), epoch))
            .await
        {
            Some(Record::Registration(record)) => Some(record),
            None => None,
            record => panic!("expected a registration record, found {record:?}"),
        };
        let status = self.status().await;
        operator.release_recovery(record.as_ref(), &status).unwrap();
    }

    /// Admits the close and verifies its certified finalization.
    async fn admit(&self, result: &SettlementResult) {
        self.control
            .submit(SettlementTx::Admit(AdmitRequest::from(result)))
            .await;
        let deadline = result.context.challenge_deadline();
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

    /// Resolves this output against one controlled current harness state.
    async fn claim_withdrawal(
        &self,
        context: &deterministic::Context,
        _source_batch: BatchId<Digest>,
        claim: &WithdrawalClaim<Digest>,
    ) -> Option<WithdrawalResponse> {
        use crate::chain::query::{Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse};
        let mut client = client::Client::new(
            self.control.identity(),
            deployment(),
            vec![SocketAddr::from(([127, 0, 0, 1], 9_800))],
            context.child("claim_status"),
        )
        .ok()?;
        let status = ChainBackend::payout_status(&mut client, context, claim.position())
            .await
            .ok()?;
        let head = status.head;
        let EvidenceResponse::Served(Evidence::Payout(refreshed)) = self
            .control
            .evidence(EvidenceRequest {
                deployment: deployment(),
                lookup: EvidenceLookup::Payout {
                    head,
                    index: claim.position(),
                },
            })
            .await
        else {
            return None;
        };
        let output = refreshed.verify::<Sha256>(&head).ok()?;
        if output != *claim.output() || refreshed.position() != claim.position() {
            return None;
        }
        if status.claimed.is_none() {
            self.control
                .submit(SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                    deployment: deployment(),
                    claim: refreshed,
                }))
                .await;
            ChainBackend::payout_status(&mut client, context, claim.position())
                .await
                .ok()?
                .claimed?;
        }
        Some(output.into())
    }
}

fn amount(value: u64) -> WithdrawalAction {
    WithdrawalAction::Amount(NonZeroU64::new(value).unwrap())
}

/// Cuts the live epoch, first adopting the registration a chain would
/// certify for it when the epoch has work to close.
fn start_current_close(operator: &mut Operator) -> Result<CloseStarted> {
    let epoch = operator.registration.context.payment().epoch();
    if operator.registration.floors.is_none() && operator.store.has_current_work()? {
        operator.adopt_at(0, None)?;
    }
    operator.start_close(epoch)
}

/// Observes `events` as consecutive certified inbox entries from index `start`.
fn observe(
    operator: &mut Operator,
    start: u64,
    events: &[DepositEvent],
) -> Result<Vec<StagedDeposit>> {
    let records = events
        .iter()
        .cloned()
        .map(Intake::Deposit)
        .collect::<Vec<_>>();
    operator.observe(start, &records)
}

fn rotate_epoch(operator: &mut Operator, epoch: u64) {
    let (successor, takes) = operator.successor().unwrap();
    operator
        .store
        .rotate_epoch(
            epoch,
            operator.registration.context.payment(),
            &successor.context,
            &takes,
            operator.registration.intake.end,
        )
        .unwrap();
    operator.registration = successor;
    operator.validate_current_epoch().unwrap();
}

/// Releases restart intake as a healthy chain would: every cut epoch is
/// registered, and so is the live epoch exactly when it was adopted.
fn release(operator: &mut Operator) {
    let epoch = operator.registration.context.payment().epoch();
    let record = operator
        .registration
        .floors
        .map(|floors| RegistrationRecord {
            epoch,
            anchor: *operator.registration.context.payment().anchor(),
            height: 0,
            deadlines: operator.registration.deadlines,
            deposits_root: operator.registration.deposits.root::<Sha256>().unwrap(),
            withdrawals_root: operator.registration.withdrawals.root::<Sha256>().unwrap(),
            pulled: operator.registration.intake.clone(),
            intake: operator.registration.intake.end,
            floors,
            admitted: None,
        });
    let status = StatusRecord {
        height: 0,
        timestamp: 0,
        deployment: deployment(),
        state_root: operator.genesis.root(),
        last_finalized: None,
        next_admission: epoch,
        next_registration: epoch + u64::from(record.is_some()),
        intake: 0,
        pulled: 0,
        custody: 0,
        claimable: 0,
        hard_faulted: false,
    };
    operator.release_recovery(record.as_ref(), &status).unwrap();
}

#[test]
fn send_sequence_rejects_the_whole_fresh_suffix() {
    let mut operator = operator();
    let recipient = operator.wallets[1].public_key();
    let first = operator.sign_send(0, &[(recipient.clone(), 1)]).unwrap();
    let endpoint = Endpoint {
        seq: 1,
        cumulative_debit: 1,
        entries: vec![OutEntry {
            recipient: recipient.clone(),
            cumulative: 1,
            count: 1,
        }],
    };
    let second = sign_send_at(
        operator.registration.context.payment(),
        operator
            .store
            .predecessor(&operator.wallets[0].public_key())
            .unwrap(),
        &operator.wallets[0],
        &endpoint,
        &[(recipient, INITIAL_BALANCE)],
    )
    .unwrap();
    let result = operator.accept_sends(operator_rpc::AcceptSendsRequest {
        sends: [first, second]
            .into_iter()
            .map(|(authorization, entries)| operator_rpc::AcceptSendRequest {
                authorization,
                entries,
            })
            .collect(),
    });
    assert!(result.is_err());
    assert!(operator.snapshot().unwrap().payments.is_empty());
}

#[test]
fn payment_group_commit_unknown_recovers_all_members() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let first = operator
        .sign_send(0, &[(operator.wallets[2].public_key(), 1)])
        .unwrap();
    let second = operator
        .sign_send(1, &[(operator.wallets[2].public_key(), 1)])
        .unwrap();
    operator.fail_next_payment_commit();
    let requests = [first, second]
        .into_iter()
        .map(
            |(authorization, entries)| operator_rpc::AcceptSendsRequest {
                sends: vec![operator_rpc::AcceptSendRequest {
                    authorization,
                    entries,
                }],
            },
        )
        .collect();
    let verified = verify_sends(
        requests,
        &mut commonware_utils::test_rng(),
        &operator.payment_strategy(),
    )
    .into_iter()
    .collect::<Result<Vec<_>>>()
    .unwrap();
    let result = operator.accept_verified_sends(verified);
    assert!(result.is_err());
    assert!(operator.fault().is_some());
    drop(operator);

    let operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(operator.snapshot().unwrap().payments.len(), 2);
}

type SignedSend = (SendAuthorization<Key, Digest>, Vec<Entry>);

fn submit_group(
    operator: &mut Operator,
    batches: Vec<Vec<SignedSend>>,
) -> Result<Vec<Result<SendsOutcome>>> {
    let requests = batches
        .into_iter()
        .map(|batch| operator_rpc::AcceptSendsRequest {
            sends: batch
                .into_iter()
                .map(|(authorization, entries)| operator_rpc::AcceptSendRequest {
                    authorization,
                    entries,
                })
                .collect(),
        })
        .collect();
    let verified = verify_sends(
        requests,
        &mut commonware_utils::test_rng(),
        &operator.payment_strategy(),
    )
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    operator.accept_verified_sends(verified)
}

#[test]
fn payment_group_adds_hot_recipient_credits_and_reuses_them_in_order() {
    let mut operator = operator();
    operator.pay(1, 2, INITIAL_BALANCE).unwrap();
    let shared = operator.wallets[1].public_key();
    let receiver = operator.wallets[2].public_key();
    let first = operator.sign_send(0, &[(shared.clone(), 7)]).unwrap();
    let second = operator.sign_send(2, &[(shared.clone(), 5)]).unwrap();
    let reuse = operator.sign_send(1, &[(receiver, 12)]).unwrap();
    let results =
        submit_group(&mut operator, vec![vec![first], vec![second], vec![reuse]]).unwrap();
    assert!(
        results
            .into_iter()
            .all(|result| matches!(result, Ok(SendsOutcome::Accepted(_))))
    );
    assert_eq!(
        operator
            .store
            .current_account(&shared)
            .unwrap()
            .unwrap()
            .current,
        0
    );
    assert_eq!(operator.store.current_entry_count().unwrap(), 4);
    operator.validate_current_epoch().unwrap();
}

#[test]
fn payment_group_rejects_one_payer_atomically_and_commits_another() {
    let mut operator = operator();
    let receiver = operator.wallets[2].public_key();
    let first = operator.sign_send(0, &[(receiver.clone(), 1)]).unwrap();
    let second = sign_send_at(
        operator.registration.context.payment(),
        operator
            .store
            .predecessor(&operator.wallets[0].public_key())
            .unwrap(),
        &operator.wallets[0],
        &Endpoint {
            seq: 1,
            cumulative_debit: 1,
            entries: vec![OutEntry {
                recipient: receiver.clone(),
                cumulative: 1,
                count: 1,
            }],
        },
        &[(receiver.clone(), INITIAL_BALANCE)],
    )
    .unwrap();
    let other = operator.sign_send(1, &[(receiver, 3)]).unwrap();
    let results = submit_group(&mut operator, vec![vec![first, second], vec![other]]).unwrap();
    assert!(results[0].is_err());
    assert!(matches!(&results[1], Ok(SendsOutcome::Accepted(accepted)) if accepted.len() == 1));
    assert_eq!(
        operator
            .store
            .payer_endpoint(&operator.wallets[0].public_key())
            .unwrap()
            .seq,
        0
    );
    assert_eq!(operator.store.current_entry_count().unwrap(), 1);
    operator.validate_current_epoch().unwrap();
}

#[test]
fn payment_batch_replays_its_prefix_and_commits_only_the_fresh_suffix() {
    let mut operator = operator();
    let recipient = operator.wallets[1].public_key();
    let first = operator.sign_send(0, &[(recipient.clone(), 1)]).unwrap();
    let first_accepted = operator
        .accept_send(first.0.clone(), first.1.clone())
        .unwrap()
        .into_accepted();
    let second = operator.sign_send(0, &[(recipient, 2)]).unwrap();
    let request = operator_rpc::AcceptSendsRequest {
        sends: vec![first, second]
            .into_iter()
            .map(|(authorization, entries)| operator_rpc::AcceptSendRequest {
                authorization,
                entries,
            })
            .collect(),
    };
    let accepted = match operator.accept_sends(request.clone()).unwrap() {
        SendsOutcome::Accepted(accepted) => accepted,
        SendsOutcome::Stale { .. } => panic!("the suffix extends the live endpoint"),
    };
    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[0].acceptance, first_accepted.acceptance);
    let replay = match operator.accept_sends(request).unwrap() {
        SendsOutcome::Accepted(accepted) => accepted,
        SendsOutcome::Stale { .. } => panic!("exact replay must remain accepted"),
    };
    assert_eq!(
        accepted
            .iter()
            .map(|batch| &batch.acceptance)
            .collect::<Vec<_>>(),
        replay
            .iter()
            .map(|batch| &batch.acceptance)
            .collect::<Vec<_>>()
    );
    assert_eq!(operator.store.current_entry_count().unwrap(), 2);
    operator.validate_current_epoch().unwrap();
}

#[test]
fn payment_group_write_failure_rolls_back_every_payer_and_fences() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let recipient = operator.wallets[2].public_key();
    let first = operator.sign_send(0, &[(recipient.clone(), 1)]).unwrap();
    let second = operator.sign_send(1, &[(recipient, 2)]).unwrap();
    operator.store.fail_next_payment_write();
    assert!(submit_group(&mut operator, vec![vec![first], vec![second]]).is_err());
    assert!(operator.fault().is_some());
    drop(operator);
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(operator.store.current_entry_count().unwrap(), 0);
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
        operator
            .balances
            .as_ref()
            .unwrap()
            .opening(1, &receiver)
            .unwrap()
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
fn payment_head_reads_the_live_ledger_without_replaying_accepted_entries() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::new(2).unwrap()).unwrap();
    let payer = operator.wallets[0].public_key();
    let before = operator.payment_head(&payer).unwrap();
    for amount in [3, 4, 5] {
        operator.pay(0, 1, amount).unwrap();
    }

    // Accepted payments advance the live balance within one signing context.
    let after = operator.payment_head(&payer).unwrap();
    assert_eq!(after.context, before.context);
    assert_eq!(after.balance, before.balance - 12);
    assert_eq!(
        operator
            .store
            .payer_endpoint(&payer)
            .unwrap()
            .cumulative_debit,
        12
    );

    // Head reads use the materialized ledger; startup authenticates its immutable
    // acknowledgment log before accepting new work.
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
    assert_eq!(reread.context, after.context);
    assert_eq!(reread.balance, after.balance);
    drop(operator);
    drop(connection);

    let error = match Operator::open(database.path(), NonZeroUsize::new(2).unwrap()) {
        Ok(_) => panic!("tampered acknowledgment log reopened cleanly"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("verify stored acknowledgment"));
}

#[test]
fn finalized_result_and_live_balance_survive_restart() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    operator.pay(0, 1, 7).unwrap();
    operator.complete_close(21).unwrap();
    let root = operator.balances.as_ref().unwrap().root(1).unwrap();
    drop(operator);

    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();

    assert_eq!(operator.balances.as_ref().unwrap().root(1).unwrap(), root);
}

#[test]
fn historical_replica_proofs_do_not_change_operator_accounting() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let payer = operator.wallets[0].public_key();
    let genesis = operator.balances.as_ref().unwrap().root(0).unwrap();
    operator.pay(0, 1, 7).unwrap();
    operator.complete_close(19).unwrap();
    let successor = operator.balances.as_ref().unwrap().root(1).unwrap();
    drop(operator);

    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    for (epoch, root, balance) in [
        (0, genesis, INITIAL_BALANCE),
        (1, successor, INITIAL_BALANCE - 7),
    ] {
        let opening = operator
            .balances
            .as_ref()
            .unwrap()
            .opening(epoch, &payer)
            .unwrap();
        assert_eq!(opening.verify::<Sha256>(&root).unwrap().get(), balance);
        assert!(
            operator
                .balances
                .as_ref()
                .unwrap()
                .opening(epoch, &eve_identity().key)
                .is_err()
        );
    }
    assert!(
        operator
            .balances
            .as_ref()
            .unwrap()
            .opening(2, &payer)
            .is_err()
    );
    assert_eq!(
        operator.balances.as_ref().unwrap().root(1).unwrap(),
        successor
    );
    operator.pay(0, 1, 3).unwrap();
    operator.complete_close(20).unwrap();
    let expected = operator.balances.as_ref().unwrap().root(2).unwrap();
    drop(operator);

    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert_eq!(
        operator.balances.as_ref().unwrap().root(2).unwrap(),
        expected
    );
    assert_eq!(
        operator.payment_head(&payer).unwrap().balance,
        INITIAL_BALANCE - 10
    );
    let opening = operator
        .balances
        .as_ref()
        .unwrap()
        .opening(0, &payer)
        .unwrap();
    assert_eq!(
        opening.verify::<Sha256>(&genesis).unwrap().get(),
        INITIAL_BALANCE
    );
}

#[test]
fn certified_close_survives_unknown_retention_commit_without_recertification() {
    let database = TempDatabase::new();
    let saved;
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        operator.pay(0, 1, 7).unwrap();
        operator.fail_next_result_commit();
        start_current_close(&mut operator).unwrap();
        let error = operator
            .wait_for_closes()
            .err()
            .expect("injected unknown commit completed");
        assert!(error.downcast_ref::<CommitUnknown>().is_some(), "{error:#}");
        assert!(operator.ensure_store_usable().is_err());
        assert!(operator.store.failed_close().unwrap().is_none());
        assert_eq!(operator.store.closing_epoch_from(0).unwrap(), Some(0));
        saved = operator.store.stored_result(0).unwrap().unwrap().encode();
    }
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let closes = operator.wait_for_closes().unwrap();
    assert!(matches!(closes.as_slice(), [CloseEvent::Finished(close)] if close.epoch == 0));
    assert_eq!(
        operator.store.stored_result(0).unwrap().unwrap().encode(),
        saved
    );
    release(&mut operator);
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
            .resolve::<Sha256>(
                &activity_range(&operator, 0),
                &payer,
                &operator.wallets[1].public_key()
            )
            .unwrap(),
        (7, 1)
    );
}

#[test]
fn retained_certified_close_rejects_replacement_and_preserves_exact_bytes() {
    let mut operator = operator();
    operator.pay(0, 1, 7).unwrap();
    admit_pending(&mut operator);
    let mut result = operator.store.stored_result(0).unwrap().unwrap();
    let saved = result.encode();
    operator
        .store
        .record_result(&result, operator.genesis.root())
        .unwrap();
    result.prepare_micros += 1;
    let error = operator
        .store
        .record_result(&result, operator.genesis.root())
        .unwrap_err();
    assert!(format!("{error:#}").contains("conflicts with retained result"));
    assert_eq!(
        operator.store.stored_result(0).unwrap().unwrap().encode(),
        saved
    );
    assert_eq!(
        operator
            .payment_head(&operator.wallets[0].public_key())
            .unwrap()
            .balance,
        INITIAL_BALANCE - 7
    );
}

#[test]
fn certified_closes_progress_while_the_proof_replica_is_held() {
    let mut operator = operator();
    let (started, release) = operator
        .balances
        .as_ref()
        .unwrap()
        .pause_next_catch_up()
        .unwrap();
    for epoch in 0..6 {
        operator.pay(0, 1, 1).unwrap();
        start_current_close(&mut operator).unwrap();
        let events = operator.wait_for_closes().unwrap();
        assert!(matches!(events.as_slice(), [CloseEvent::Finished(close)] if close.epoch == epoch));
        if epoch == 0 {
            started.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        assert_eq!(
            operator.store.latest_finalized_root().unwrap().unwrap().0,
            epoch
        );
        assert_eq!(
            operator
                .store
                .current_account(&operator.wallets[0].public_key())
                .unwrap()
                .unwrap()
                .current,
            INITIAL_BALANCE - epoch - 1
        );
    }
    assert_eq!(
        operator.store.epoch_reader().load(0).unwrap().edges.len(),
        1
    );
    release.send(()).unwrap();
    operator.balances.as_ref().unwrap().catch_up().unwrap();
    for epoch in 0..=6 {
        let root = operator.balances.as_ref().unwrap().root(epoch).unwrap();
        let opening = operator
            .balances
            .as_ref()
            .unwrap()
            .opening(epoch, &operator.wallets[0].public_key())
            .unwrap();
        assert_eq!(
            opening.verify::<Sha256>(&root).unwrap().get(),
            INITIAL_BALANCE - epoch
        );
    }
}

/// A failed asynchronous proof retirement fences foreground payments.
///
/// Epoch 0 finalizes, which keeps its vectors while epoch 1 is live. Epoch 1's catch-up then
/// retires epoch 0's vectors, and an injected SQL failure there fences the whole operator.
#[test]
fn asynchronous_proof_sql_failure_fences_foreground_payments() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();

    // Epoch 0 carries one accepted send and finalizes.
    let (send, entries) = operator
        .sign_send(0, &[(operator.wallets[1].public_key(), 7)])
        .unwrap();
    operator.accept_send(send.clone(), entries.clone()).unwrap();
    operator.complete_close(73).unwrap();
    assert_eq!(operator.store.outgoing_entry_count(0).unwrap(), 1);

    // Epoch 1's close finishes while its catch-up waits before retiring epoch 0's vectors.
    operator.pay(0, 1, 1).unwrap();
    let (started, release) = operator
        .balances
        .as_ref()
        .unwrap()
        .pause_next_catch_up()
        .unwrap();
    start_current_close(&mut operator).unwrap();
    operator.wait_for_closes().unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    // The retirement fails, and every foreground operation is fenced.
    let connection = rusqlite::Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_proof_retirement BEFORE DELETE ON out_entries
         BEGIN SELECT RAISE(ABORT, 'injected proof retirement failure'); END;",
        )
        .unwrap();
    release.send(()).unwrap();
    assert!(operator.balances.as_ref().unwrap().catch_up().is_err());
    assert!(operator.pay(0, 1, 1).is_err());
    assert!(operator.ensure_store_usable().is_err());
    assert!(operator.accepted_batch(&send, &entries).is_err());
    assert!(operator.store.epoch_reader().load(1).is_err());
    assert!(operator.fault().is_some());
}

#[test]
fn certified_sql_inputs_recover_native_replica_before_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let chain = Chain::new(&context).await;
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        chain.register(&mut operator).await;
        operator.pay(0, 1, 7).unwrap();
        let prepared = operator
            .prepare_epoch(
                operator.store.load_current().unwrap(),
                operator.registration.clone(),
            )
            .unwrap();
        rotate_epoch(&mut operator, 0);
        let result = operator
            .protocol
            .fixture_complete(&operator.initial_accounts, &[], prepared, 73)
            .unwrap();
        operator
            .store
            .record_result(&result, operator.genesis.root())
            .unwrap();
        chain
            .control
            .submit(SettlementTx::Admit(AdmitRequest::from(&result)))
            .await;
        let Some(Record::Admitted(record)) =
            chain.control.record(admitted_key(&deployment(), 0)).await
        else {
            panic!("certified close was not admitted");
        };
        assert_eq!(record.batch_id, result.header.batch_id::<Sha256>());
        assert_eq!(record.roots, result.roots);
        assert!(!record.finalized);
        let admitted = AdmittedRootsResponse {
            batch_id: record.batch_id,
            roots: record.roots,
            activity_start: record.activity_start,
            finalized: record.finalized,
        };
        operator.record_admission(&result).unwrap();
        assert!(operator.store.latest_finalized_root().unwrap().is_none());
        let saved = result.encode();
        drop(operator);

        let recovered = reopen_admitted(&context, database.path(), [(0, admitted)].into()).await;
        assert_eq!(
            recovered.balances.as_ref().unwrap().startup_work().unwrap(),
            (vec![1], vec![1])
        );
        assert_eq!(
            recovered.store.stored_result(0).unwrap().unwrap().encode(),
            saved
        );
        let opening = recovered
            .balances
            .as_ref()
            .unwrap()
            .opening(1, &recovered.wallets[0].public_key())
            .unwrap();
        assert_eq!(
            opening
                .verify::<Sha256>(&result.roots.successor)
                .unwrap()
                .get(),
            INITIAL_BALANCE - 7
        );
        drop(recovered);

        let recovered = reopen_admitted(&context, database.path(), [(0, admitted)].into()).await;
        assert_eq!(
            recovered.balances.as_ref().unwrap().startup_work().unwrap(),
            (vec![], vec![])
        );
        assert_eq!(
            recovered.balances.as_ref().unwrap().root(1).unwrap(),
            result.roots.successor
        );
    });
}

#[test]
fn operator_store_has_one_live_owner() {
    let database = TempDatabase::new();
    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(Operator::open(database.path(), NonZeroUsize::MIN).is_err());
    drop(operator);
    let operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    assert!(operator.fault().is_none());
}

#[test]
fn operator_paths_with_shared_stem_keep_distinct_proof_replicas() {
    let database = TempDatabase::new();
    let other_path = database.path().with_extension("db");
    let mut first = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let mut second = Operator::open(&other_path, NonZeroUsize::MIN).unwrap();
    first.pay(0, 1, 7).unwrap();
    second.pay(0, 1, 13).unwrap();
    first.complete_close(1).unwrap();
    second.complete_close(2).unwrap();
    let payer = first.wallets[0].public_key();
    assert_eq!(
        first.payment_head(&payer).unwrap().balance,
        INITIAL_BALANCE - 7
    );
    assert_eq!(
        second.payment_head(&payer).unwrap().balance,
        INITIAL_BALANCE - 13
    );
    assert_ne!(
        first.balances.as_ref().unwrap().root(1).unwrap(),
        second.balances.as_ref().unwrap().root(1).unwrap()
    );
}

#[test]
fn payments_continue_while_the_successor_proof_is_unavailable() {
    let mut operator = operator();
    operator.pay(0, 1, 7).unwrap();
    let (started, release) = operator.pause_next_close();
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let payer = operator.wallets[0].public_key();

    // The head floors at the last certified root, so it does not wait for
    // the paused close to build the successor checkpoint.
    let head = operator.payment_head(&payer).unwrap();
    assert_eq!(head.context.payment().epoch(), 1);
    assert_eq!(head.floor_epoch, 0);
    assert_eq!(head.root, operator.genesis.root());
    assert_eq!(head.balance, INITIAL_BALANCE - 7);
    assert_eq!(operator.pay(0, 1, 3).unwrap().epoch, 1);
    release.send(()).unwrap();
    operator.wait_for_closes().unwrap();
    let head = operator.payment_head(&payer).unwrap();
    assert_eq!(head.balance, INITIAL_BALANCE - 10);
    assert_eq!(
        operator
            .balances
            .as_ref()
            .unwrap()
            .opening(1, &payer)
            .unwrap()
            .verify::<Sha256>(&operator.balances.as_ref().unwrap().root(1).unwrap())
            .unwrap()
            .get(),
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
    // rejection carrying the live context and the payer's endpoint in the dead send's
    // own epoch, never a debit.
    let mut honest = operator();
    let (dead, dead_entries) = honest.sign_send(0, &[(receiver.clone(), 7)]).unwrap();

    // An unrelated payment gives the epoch content to close. The payer's send was
    // never accepted, so the cut commits nothing of it.
    honest.pay(2, 3, 5).unwrap();
    rotate_epoch(&mut honest, 0);
    let (retry, retry_entries) = honest.sign_send(0, &[(receiver, 7)]).unwrap();
    let committed = honest
        .accept_send(retry, retry_entries)
        .unwrap()
        .into_accepted();
    assert_eq!(committed.total, 7);
    match honest.accept_send(dead, dead_entries).unwrap() {
        SendOutcome::Stale { context, report } => {
            assert_eq!(&context, honest.registration.context.payment());
            assert_eq!(report.epoch, 0);
            assert_eq!(
                (report.endpoint.seq, report.endpoint.cumulative_debit),
                (0, 0)
            );
            assert!(report.endpoint.entries.is_empty());
            assert_eq!(
                report.predecessor,
                commitment::empty_root::<Sha256>(VectorKind::OutEntry)
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

/// The root of one payer's cumulative vector.
fn vector_root(payer: &Key, entries: Vec<OutEntry<Key>>) -> VectorRoot<Digest> {
    OutVector::new(0, payer.clone(), entries)
        .unwrap()
        .root::<Sha256, Digest>()
        .unwrap()
}

/// Bodies of the live epoch must bind the payer's frozen terminal root in the cut epoch.
///
/// Wallet 0 pays in epoch 0, so its epoch-1 bodies must bind the root of that terminal. Wallet
/// 1 pays nothing there and must bind the empty vector root. A body bound to any other root
/// earns a report naming the required root and moves no balance, and one submission cannot
/// bind two predecessors.
#[test]
fn acceptance_requires_frozen_predecessor() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let idle = operator.wallets[1].public_key();
    let receiver = operator.wallets[2].public_key();
    let empty = commitment::empty_root::<Sha256>(VectorKind::OutEntry);

    // Wallet 0 pays in epoch 0, and the cut freezes the root of its terminal vector.
    operator.pay(0, 2, 5).unwrap();
    let frozen = vector_root(
        &payer,
        operator.store.payer_endpoint(&payer).unwrap().entries,
    );
    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.predecessor(&payer).unwrap(), frozen);
    assert_eq!(operator.store.predecessor(&idle).unwrap(), empty);

    // Bodies bound to another root earn a report naming the required root.
    let context = operator.registration.context.payment().clone();
    let none = Endpoint {
        cumulative_debit: 0,
        seq: 0,
        entries: Vec::new(),
    };
    for (wallet, wrong, required) in [(0, empty, frozen), (1, frozen, empty)] {
        let account = operator.wallets[wallet].public_key();
        let (send, entries) = sign_send_at(
            &context,
            wrong,
            &operator.wallets[wallet],
            &none,
            &[(receiver.clone(), 1)],
        )
        .unwrap();
        let before = operator.store.current_account(&account).unwrap().unwrap();
        match operator.accept_send(send, entries).unwrap() {
            SendOutcome::Stale { report, .. } => {
                assert_eq!(report.epoch, 1);
                assert_eq!(report.predecessor, required);
            }
            SendOutcome::Accepted(_) => panic!("a body bound to another predecessor was accepted"),
        }
        let after = operator.store.current_account(&account).unwrap().unwrap();
        assert_eq!(after.current, before.current);
    }

    // A submission whose sends bind different predecessors is refused before acceptance.
    let first = sign_send_at(
        &context,
        frozen,
        &operator.wallets[0],
        &none,
        &[(receiver.clone(), 1)],
    )
    .unwrap();
    let second = sign_send_at(
        &context,
        empty,
        &operator.wallets[0],
        &Endpoint {
            cumulative_debit: 1,
            seq: 1,
            entries: vec![OutEntry {
                recipient: receiver.clone(),
                cumulative: 1,
                count: 1,
            }],
        },
        &[(receiver.clone(), 1)],
    )
    .unwrap();
    let mixed = operator.accept_sends(operator_rpc::AcceptSendsRequest {
        sends: [first, second]
            .into_iter()
            .map(|(authorization, entries)| operator_rpc::AcceptSendRequest {
                authorization,
                entries,
            })
            .collect(),
    });
    assert!(format!("{:#}", mixed.err().unwrap()).contains("more than one predecessor"));

    // Bodies bound to the frozen roots are accepted, and each receipt countersigns the
    // predecessor it binds.
    for (wallet, required) in [(0, frozen), (1, empty)] {
        let (send, entries) = sign_send_at(
            &context,
            required,
            &operator.wallets[wallet],
            &none,
            &[(receiver.clone(), 1)],
        )
        .unwrap();
        let accepted = operator.accept_send(send, entries).unwrap().into_accepted();
        assert_eq!(accepted.acceptance.ack.predecessor(), required);
        accepted.acceptance.verify(&context).unwrap();
    }
}

/// A send that arrives after its epoch is cut reports the payer's frozen endpoint in that
/// epoch, never the live one, together with the root the live epoch requires.
#[test]
fn stale_after_cut_reports_frozen_endpoint() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    let receiver = operator.wallets[2].public_key();

    // Wallet 0 pays twice in epoch 0 and signs a third send that arrives only after the cut.
    operator.pay(0, 2, 5).unwrap();
    operator.pay(0, 1, 3).unwrap();
    let frozen = operator.store.payer_endpoint(&payer).unwrap();
    let (late, late_entries) = operator.sign_send(0, &[(receiver, 2)]).unwrap();
    rotate_epoch(&mut operator, 0);

    // Wallet 0 pays in epoch 1, so its live endpoint differs from the frozen one.
    operator.pay(0, 2, 7).unwrap();
    let live = operator.store.payer_endpoint(&payer).unwrap();
    assert_eq!((live.seq, live.cumulative_debit), (1, 7));
    let balance = operator
        .store
        .current_account(&payer)
        .unwrap()
        .unwrap()
        .current;

    // The late send reports epoch 0's frozen endpoint and the root epoch 1 requires.
    match operator.accept_send(late, late_entries).unwrap() {
        SendOutcome::Stale { context, report } => {
            assert_eq!(&context, operator.registration.context.payment());
            assert_eq!(report.epoch, 0);
            assert_eq!(
                (report.endpoint.seq, report.endpoint.cumulative_debit),
                (2, 8)
            );
            assert_eq!(report.endpoint.entries, frozen.entries);
            assert_eq!(report.predecessor, vector_root(&payer, frozen.entries));
        }
        SendOutcome::Accepted(_) => panic!("a send of a cut epoch was accepted"),
    }
    assert_eq!(
        operator
            .store
            .current_account(&payer)
            .unwrap()
            .unwrap()
            .current,
        balance
    );
}

/// A late send keeps its report after its own epoch finalizes, until the next epoch finalizes.
///
/// Wallet 0 pays in epoch 0 and holds back a second send. Epoch 0's close finalizes while epoch
/// 1 is live, and the late send still reports epoch 0's frozen endpoint. Once epoch 1 finalizes,
/// epoch 0's vectors are retired and the late send is refused instead.
#[test]
fn stale_reports_survive_until_the_next_epoch_finalizes() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    let payer = operator.wallets[0].public_key();
    let receiver = operator.wallets[2].public_key();

    // Wallet 0 pays in epoch 0 and signs a late send, and epoch 0 finalizes.
    operator.pay(0, 2, 5).unwrap();
    let frozen = operator.store.payer_endpoint(&payer).unwrap();
    let (late, late_entries) = operator.sign_send(0, &[(receiver, 2)]).unwrap();
    operator.complete_close(71).unwrap();
    operator.balances.as_ref().unwrap().catch_up().unwrap();

    // The late send reports epoch 0's frozen endpoint while epoch 1 is live.
    match operator
        .accept_send(late.clone(), late_entries.clone())
        .unwrap()
    {
        SendOutcome::Stale { report, .. } => {
            assert_eq!(report.epoch, 0);
            assert_eq!(
                (report.endpoint.seq, report.endpoint.cumulative_debit),
                (1, 5)
            );
            assert_eq!(report.endpoint.entries, frozen.entries);
        }
        SendOutcome::Accepted(_) => panic!("a send of a finalized epoch was accepted"),
    }

    // Epoch 1's finality retires epoch 0's vectors, so the late send is refused.
    operator.pay(1, 2, 1).unwrap();
    operator.complete_close(72).unwrap();
    operator.balances.as_ref().unwrap().catch_up().unwrap();
    assert!(operator.accept_send(late, late_entries).is_err());
}

/// Frozen predecessors survive a restart.
///
/// The operator restarts with epoch 0 cut and its close still pending. A late epoch-0 send
/// still reports the frozen endpoint, and epoch 1 still accepts only bodies bound to the
/// frozen root.
#[test]
fn frozen_predecessors_survive_restart() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let database = TempDatabase::new();
        let chain = Chain {
            control: harness::start_with_native(
                &context,
                SocketAddr::from(([127, 0, 0, 1], 9_800)),
                "chain",
                harness::native(crate::protocol::deployments()),
                Timing {
                    admission_offset: 1_000,
                    challenge_duration: 8,
                },
            )
            .await,
        };
        let payer = wallets()[0].public_key();
        let receiver = wallets()[2].public_key();

        // Epoch 0 registers and wallet 0 pays. A second epoch-0 send is held back, and the cut
        // holds the close before preparation.
        let (late, late_entries, frozen) = {
            let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
            chain.register(&mut operator).await;
            operator.pay(0, 2, 5).unwrap();
            let frozen = operator.store.payer_endpoint(&payer).unwrap();
            let (late, late_entries) = operator.sign_send(0, &[(receiver.clone(), 2)]).unwrap();
            let (started, resume) = operator.pause_next_close();
            operator.start_close(0).unwrap();
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(resume);
            (late, late_entries, frozen)
        };
        let root = vector_root(&payer, frozen.entries.clone());

        // The reopened operator authenticates epoch 1 and adopts its registration.
        let mut operator = reopen_held(&context, database.path());
        chain.release(&mut operator).await;
        chain.register(&mut operator).await;
        assert_eq!(operator.store.predecessor(&payer).unwrap(), root);

        // The late send reports the frozen endpoint and the root epoch 1 requires.
        match operator.accept_send(late, late_entries).unwrap() {
            SendOutcome::Stale { report, .. } => {
                assert_eq!(report.epoch, 0);
                assert_eq!(
                    (report.endpoint.seq, report.endpoint.cumulative_debit),
                    (1, 5)
                );
                assert_eq!(report.endpoint.entries, frozen.entries);
                assert_eq!(report.predecessor, root);
            }
            SendOutcome::Accepted(_) => panic!("a send of a cut epoch was accepted after restart"),
        }

        // Epoch 1 refuses a body bound to the empty root and accepts one bound to the frozen
        // root.
        let (wrong, wrong_entries) = sign_send_at(
            &operator.registration.context.payment().clone(),
            commitment::empty_root::<Sha256>(VectorKind::OutEntry),
            &operator.wallets[0],
            &Endpoint {
                cumulative_debit: 0,
                seq: 0,
                entries: Vec::new(),
            },
            &[(receiver.clone(), 1)],
        )
        .unwrap();
        assert!(matches!(
            operator.accept_send(wrong, wrong_entries).unwrap(),
            SendOutcome::Stale { .. }
        ));
        let accepted = operator.pay(0, 2, 1).unwrap();
        assert_eq!(accepted.epoch, 1);
        assert_eq!(accepted.acceptance.ack.predecessor(), root);
    });
}

/// A close is proposed only when every terminal binds its payer's root in the frozen
/// acknowledgments of the preceding epoch, which built the preceding close.
///
/// Wallet 0 pays in epoch 0, whose close certifies, and again in epoch 1. The tampered run
/// replaces the stored epoch-1 acknowledgment with one bound to another root and validly
/// signed by both keys. Its close fences the operator before it reaches validators, while the
/// untouched close certifies through validators that read the predecessor from epoch 0's rows.
#[test]
fn successor_terminals_match_predecessor_close() {
    for tampered in [false, true] {
        let mut operator = operator();
        let payer = operator.wallets[0].public_key();

        // Epoch 0 closes, and wallet 0 pays in epoch 1 bound to its epoch-0 terminal.
        operator.pay(0, 2, 5).unwrap();
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
        assert!(operator.fault().is_none());
        let accepted = operator.pay(0, 2, 3).unwrap();
        assert_eq!(accepted.epoch, 1);
        assert_eq!(
            accepted.acceptance.ack.predecessor(),
            vector_root(
                &payer,
                vec![OutEntry {
                    recipient: operator.wallets[2].public_key(),
                    cumulative: 5,
                    count: 1,
                }]
            )
        );

        // The tampered run rebinds the stored acknowledgment to the empty root.
        if tampered {
            let ack = Ack::sign_by_authorities(
                accepted.acceptance.ack.body().clone(),
                commitment::empty_root::<Sha256>(VectorKind::OutEntry),
                operator.wallets[0].signer(),
                operator.protocol.operator(),
            );
            let connection = rusqlite::Connection::open(operator.store.database_path()).unwrap();
            assert_eq!(
                connection
                    .execute(
                        "UPDATE acks SET ack = ?1 WHERE epoch = 1 AND payer = ?2 AND seq = 1",
                        rusqlite::params![ack.encode().as_ref(), payer.as_ref()],
                    )
                    .unwrap(),
                1
            );
        }

        // Closing epoch 1 certifies the untouched terminal and fences the rebound one.
        start_current_close(&mut operator).unwrap();
        operator.wait_for_closes().unwrap();
        if tampered {
            let fault = operator
                .fault()
                .expect("the rebound terminal fenced the operator");
            assert!(
                fault.contains("binds another predecessor"),
                "unexpected fence: {fault}"
            );
            assert!(operator.retained_result(1).unwrap().is_none());
        } else {
            assert!(operator.fault().is_none());
            assert!(operator.retained_result(1).unwrap().is_some());
        }
    }
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
        operator
            .store
            .predecessor(&operator.wallets[0].public_key())
            .unwrap(),
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

/// Finality retires an epoch's vectors once the next epoch finalizes, while receipts, replays
/// and committed evidence stay served.
///
/// Epoch 0's close finalizes while epoch 1 is live, so both epochs keep their vectors across a
/// restart and the epoch-0 receipt replays unchanged. Epoch 1's finalization then retires epoch
/// 0's vectors and keeps its own.
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
        .prepare_epoch(
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

    // Epoch 0 finalized while epoch 1 is live, so both epochs keep their vectors.
    for restart in [false, true] {
        if restart {
            drop(operator);
            operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        }
        assert_eq!(operator.store.outgoing_entry_count(0).unwrap(), 1);
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
                .resolve::<Sha256>(&activity_range(&operator, 0), &payer, &recipient)
                .unwrap(),
            (5, 2)
        );
    }
    // Epoch 1's finalization retires epoch 0's vectors and keeps its own.
    operator.pay(1, 2, 2).unwrap();
    operator.complete_close(72).unwrap();
    operator.balances.as_ref().unwrap().catch_up().unwrap();
    assert_eq!(operator.store.outgoing_entry_count(0).unwrap(), 0);
    assert_eq!(operator.store.outgoing_entry_count(1).unwrap(), 1);
    let evidence = operator
        .committed_entry(&recipient, &operator.wallets[2].public_key(), 1)
        .unwrap();
    assert_eq!(
        evidence
            .resolve::<Sha256>(
                &activity_range(&operator, 1),
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
    assert_eq!(
        evidence
            .resolve::<Sha256>(&activity_range(&operator, epoch), &payer, &receiver)
            .unwrap(),
        (7, 1)
    );

    // A changed credit-only row resolves the reverse edge through its empty vector, and
    // a payer outside the close resolves through ordered activity absence: both
    // land on the canonical zero entry.
    let evidence = operator.committed_entry(&receiver, &payer, epoch).unwrap();
    assert_eq!(
        evidence
            .resolve::<Sha256>(&activity_range(&operator, epoch), &receiver, &payer)
            .unwrap(),
        (0, 0)
    );
    let idle = operator.wallets[3].public_key();
    let evidence = operator.committed_entry(&idle, &receiver, epoch).unwrap();
    assert_eq!(
        evidence
            .resolve::<Sha256>(&activity_range(&operator, epoch), &idle, &receiver)
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
        assert_eq!(
            evidence
                .resolve::<Sha256>(&activity_range(operator, epoch), &payer, &receiver)
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
    assert_eq!(
        retained
            .resolve::<Sha256>(&activity_range(&operator, epoch), &payer, &receiver)
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
            chain.release(&mut operator).await;
            assert_eq!(operator.signed_registration().unwrap(), request);
            chain.register(&mut operator).await;
            operator.start_close(0).unwrap();
            let events = operator.wait_for_closes().unwrap();
            match events.as_slice() {
                [CloseEvent::Finished(close)] => assert_eq!(close.epoch, 0),
                [CloseEvent::Failed { error, .. }] => panic!("{error}"),
                _ => panic!("expected exactly one close"),
            }
            let result = operator.store.stored_result(0).unwrap().unwrap();
            assert_eq!(result.roots.row_count, 0);
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

/// The close worker holds at certification and at admission while the
/// successor epoch keeps accepting payments. Certification retains the result
/// before the admission hold, and the close finishes only once released.
#[test]
fn close_holds_at_certify_and_admit_while_the_successor_pays() {
    for stage in [Stage::Certify, Stage::Admit] {
        let mut operator = operator();
        operator.pay(0, 1, 5).unwrap();

        // The worker reaches the held stage after the cut.
        let (started, release) = operator.pause_close_at(stage);
        assert_eq!(start_current_close(&mut operator).unwrap().epoch, 0);
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            operator.store.stored_result(0).unwrap().is_some(),
            stage == Stage::Admit
        );

        // The successor accepts payments while the predecessor is held.
        assert_eq!(operator.pay(1, 2, 5).unwrap().epoch, 1);
        operator.advance_close().unwrap();
        assert!(matches!(
            operator.store.close_outcome(0).unwrap(),
            StoredCloseOutcome::Pending
        ));

        // Releasing the worker finishes the close.
        release.send(()).unwrap();
        let events = operator.wait_for_closes().unwrap();
        assert!(matches!(
            events.as_slice(),
            [CloseEvent::Finished(close)] if close.epoch == 0
        ));
    }
}

/// Intake observed after the live boundary is published waits untaken,
/// because a stale signed registration stays valid. A replay stages nothing,
/// the row survives a restart, and the cutover's successor takes it only after
/// the closing epoch's withdrawal tail settles. Once the successor publishes,
/// later intake waits again.
#[test]
fn intake_after_publication_waits_for_the_successor() {
    let database = TempDatabase::new();
    let wallet = wallets().remove(0);
    let account = wallet.public_key();
    let deposit = DepositEvent {
        id: Sha256::hash(&[b"successor-deposit"]),
        account: account.clone(),
        amount: 10,
    };
    {
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();

        // Alice's close sweeps her epoch-0 tail, and epoch 0 registers.
        let opening = operator.withdrawal_opening(&account).unwrap();
        let close = SignedWithdrawal::sign(
            deployment(),
            opening.root.digest,
            account.encode(),
            WithdrawalAction::Close,
            100,
            wallet.signer(),
        );
        operator.apply_withdrawal(close, false).unwrap();
        operator.adopt_at(0, None).unwrap();
        let boundary = operator.registration.context.payment().clone();

        // The deposit is observed after publication, so epoch 0 keeps its
        // boundary and Alice keeps her balance.
        assert!(
            observe(&mut operator, 0, std::slice::from_ref(&deposit))
                .unwrap()
                .is_empty()
        );
        assert_eq!(operator.observed().unwrap(), 1);
        assert_eq!(operator.registration.context.payment(), &boundary);
        assert_eq!(operator.registration.intake, 0..0);
        assert!(operator.store.load_current().unwrap().deposits.is_empty());
        assert_eq!(
            operator.store.untaken().unwrap(),
            [(0, Intake::Deposit(deposit.clone()))]
        );
        assert_eq!(
            operator
                .store
                .current_account(&account)
                .unwrap()
                .unwrap()
                .current,
            INITIAL_BALANCE
        );

        // A replay stages nothing.
        assert!(
            observe(&mut operator, 0, std::slice::from_ref(&deposit))
                .unwrap()
                .is_empty()
        );
        assert_eq!(operator.store.untaken().unwrap().len(), 1);
        operator.ensure_store_usable().unwrap();
    }

    // The row survives a restart, still without credit.
    let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
    release(&mut operator);
    assert!(
        observe(&mut operator, 0, std::slice::from_ref(&deposit))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        operator.store.untaken().unwrap(),
        [(0, Intake::Deposit(deposit.clone()))]
    );
    assert_eq!(
        operator
            .store
            .current_account(&account)
            .unwrap()
            .unwrap()
            .current,
        INITIAL_BALANCE
    );

    // The cutover settles Alice's close against her epoch-0 tail, then its
    // successor takes the deposit, whose boundary commits it.
    let (started, resume) = operator.pause_next_close();
    assert_eq!(operator.start_close(0).unwrap().epoch, 0);
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let closing = operator.store.epoch_reader().load(0).unwrap();
    assert_eq!(closing.withdrawals.len(), 1);
    assert_eq!(closing.withdrawals[0].applied_amount, Some(INITIAL_BALANCE));
    assert_eq!(
        operator
            .store
            .current_account(&account)
            .unwrap()
            .unwrap()
            .current,
        deposit.amount
    );
    assert_eq!(
        operator.store.load_current().unwrap().deposits,
        std::slice::from_ref(&deposit)
    );
    assert_eq!(
        operator.registration.context.deposit_root(),
        &deposit_batch(std::slice::from_ref(&deposit))
            .unwrap()
            .root::<Sha256>()
            .unwrap()
    );
    assert_eq!(operator.registration.intake, 0..1);
    assert!(operator.store.untaken().unwrap().is_empty());

    // Once epoch 1 publishes, later intake waits for epoch 2.
    operator.adopt_at(1, None).unwrap();
    let live = operator.registration.context.payment().clone();
    let later = DepositEvent {
        id: Sha256::hash(&[b"registered-deposit"]),
        account,
        amount: 1,
    };
    assert!(
        observe(&mut operator, 1, std::slice::from_ref(&later))
            .unwrap()
            .is_empty()
    );
    operator.ensure_store_usable().unwrap();
    assert_eq!(operator.registration.context.payment(), &live);
    assert_eq!(operator.store.load_current().unwrap().deposits, [deposit]);
    assert_eq!(
        operator.store.untaken().unwrap(),
        [(1, Intake::Deposit(later))]
    );
    resume.send(()).unwrap();
    operator.wait_for_closes().unwrap();
}

/// An operator cuts only an epoch whose certified registration it adopted.
/// A refused cut leaves the epoch live and the operator unfenced.
#[test]
fn start_close_refuses_an_unregistered_epoch() {
    let mut operator = operator();
    operator.pay(0, 1, 5).unwrap();
    let Err(error) = operator.start_close(0) else {
        panic!("an unregistered epoch was cut");
    };
    assert!(format!("{error:#}").contains("no adopted registration"));
    assert_eq!(operator.store.epoch().unwrap(), 0);
    assert!(!operator.store.has_close_job(0).unwrap());
    assert!(operator.fault().is_none());
    assert_eq!(operator.pay(0, 1, 1).unwrap().epoch, 0);

    operator.adopt_at(0, None).unwrap();
    assert_eq!(operator.start_close(0).unwrap().epoch, 0);
    assert_eq!(operator.store.epoch().unwrap(), 1);
    operator.wait_for_closes().unwrap();
}

/// The payment head floors at the locally admitted tip while a later close
/// is held: it serves the live context and balance with the admitted
/// successor root and never waits for the held close. The floor advances as
/// the local tip does.
#[test]
fn payment_head_floors_at_the_admitted_tip_while_the_close_is_held() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    operator.pay(0, 1, 7).unwrap();
    let admitted = admit_pending(&mut operator);
    operator.pay(0, 1, 3).unwrap();

    // Epoch 1's close is held after its cut.
    let (started, resume) = operator.pause_next_close();
    assert_eq!(start_current_close(&mut operator).unwrap().epoch, 1);
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    // The head serves epoch 2 with the live balance, floored at epoch 0's
    // admitted successor.
    let head = operator.payment_head(&payer).unwrap();
    assert_eq!(head.context.payment().epoch(), 2);
    assert_eq!(head.balance, INITIAL_BALANCE - 10);
    assert_eq!(head.floor_epoch, 1);
    assert_eq!(head.root, admitted.roots.successor);
    assert_eq!(
        head.opening.verify::<Sha256>(&head.root).unwrap().get(),
        INITIAL_BALANCE - 7
    );
    assert!(operator.store.latest_finalized_root().unwrap().is_none());

    // Once epoch 0 finalizes and the released epoch 1 finishes, the floor
    // follows the local tip.
    operator.observe_finalized(0).unwrap();
    resume.send(()).unwrap();
    operator.wait_for_closes().unwrap();
    let head = operator.payment_head(&payer).unwrap();
    assert_eq!(head.floor_epoch, 2);
    assert_eq!(
        head.opening.verify::<Sha256>(&head.root).unwrap().get(),
        INITIAL_BALANCE - 10
    );
}

/// Payments proceed while a payment head waits on a held proof replica
/// catch-up: the head resolves from a snapshot that borrows nothing from the
/// operator, so replica queries never hold up intake.
#[test]
fn payments_proceed_while_a_head_waits_on_the_proof_replica() {
    let mut operator = operator();
    let payer = operator.wallets[0].public_key();
    operator.pay(0, 1, 7).unwrap();

    // The replica holds its catch-up of the finished epoch-0 close.
    let (started, release) = operator
        .balances
        .as_ref()
        .unwrap()
        .pause_next_catch_up()
        .unwrap();
    start_current_close(&mut operator).unwrap();
    operator.wait_for_closes().unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    // The head's replica read waits behind the held catch-up while epoch 1
    // keeps accepting payments.
    let snapshot = operator.head_snapshot(&payer).unwrap();
    let resolving = thread::spawn(move || snapshot.resolve());
    assert_eq!(operator.pay(0, 1, 3).unwrap().epoch, 1);
    assert_eq!(operator.pay(1, 2, 2).unwrap().epoch, 1);
    assert!(!resolving.is_finished());

    // The released replica serves the head at the finished epoch's successor.
    release.send(()).unwrap();
    let head = resolving.join().unwrap().unwrap();
    assert_eq!(head.floor_epoch, 1);
    assert_eq!(head.balance, INITIAL_BALANCE - 7);
    assert_eq!(
        head.opening.verify::<Sha256>(&head.root).unwrap().get(),
        INITIAL_BALANCE - 7
    );
}

/// Where a restart interrupts the operator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Crash {
    /// Epoch 0 is registered and pays, and nothing is cut.
    BeforeCutover,
    /// Epoch 0 is cut, and epoch 1 is unregistered.
    AfterCutover,
    /// Epoch 1's registration landed, but the operator never adopted it.
    BeforeReadback,
    /// Epoch 1 is adopted and accepted a payment, whose receipt may be lost.
    AfterReceipt,
    /// Epoch 0's certified result is retained but not admitted.
    AfterRetention,
    /// Epoch 0 is admitted but not finalized.
    AfterAdmission,
}

/// A restarted operator resumes intake once its live epoch is authenticated
/// against a healthy chain, whatever the crash point, while epoch 0 is still
/// unadmitted or unfinalized. A receipt issued before the crash replays byte
/// for byte.
#[test]
fn restart_resumes_intake_while_the_predecessor_is_held() {
    for crash in [
        Crash::BeforeCutover,
        Crash::AfterCutover,
        Crash::BeforeReadback,
        Crash::AfterReceipt,
        Crash::AfterRetention,
        Crash::AfterAdmission,
    ] {
        deterministic::Runner::timed(Duration::from_secs(60)).start(move |context| async move {
            let database = TempDatabase::new();
            let address = SocketAddr::from(([127, 0, 0, 1], 9_800));
            let chain = Chain {
                control: harness::start_with_native(
                    &context,
                    address,
                    "chain",
                    harness::native(crate::protocol::deployments()),
                    Timing {
                        admission_offset: 1_000,
                        challenge_duration: 8,
                    },
                )
                .await,
            };

            // Epoch 0 registers and pays, then the operator runs to the crash
            // point. A cut close never completes before the crash.
            let mut receipt = None;
            {
                let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
                chain.register(&mut operator).await;
                operator.pay(0, 1, 5).unwrap();
                match crash {
                    Crash::BeforeCutover => {}
                    Crash::AfterRetention => {
                        let (started, resume) = operator.pause_close_at(Stage::Admit);
                        operator.start_close(0).unwrap();
                        started.recv_timeout(Duration::from_secs(5)).unwrap();
                        drop(resume);
                    }
                    Crash::AfterAdmission => {
                        operator.start_close(0).unwrap();
                        operator.wait_for_closes().unwrap();
                        let result = operator.store.stored_result(0).unwrap().unwrap();
                        chain
                            .control
                            .submit(SettlementTx::Admit(AdmitRequest::from(&result)))
                            .await;
                    }
                    Crash::AfterCutover | Crash::BeforeReadback | Crash::AfterReceipt => {
                        let (started, resume) = operator.pause_next_close();
                        operator.start_close(0).unwrap();
                        started.recv_timeout(Duration::from_secs(5)).unwrap();
                        drop(resume);
                    }
                }
                match crash {
                    Crash::BeforeReadback => {
                        assert!(chain.try_register(&mut operator).await.is_some());
                    }
                    Crash::AfterReceipt => {
                        chain.register(&mut operator).await;
                        let recipient = operator.wallets[2].public_key();
                        let (send, entries) = operator.sign_send(1, &[(recipient, 3)]).unwrap();
                        let accepted = operator
                            .accept_send(send.clone(), entries.clone())
                            .unwrap()
                            .into_accepted();
                        receipt = Some((send, entries, accepted));
                    }
                    _ => {}
                }
            }

            // The reopened close pipeline never completes, so a pending close
            // stays held. Intake waits for authentication whenever a close is
            // pending or the live epoch was adopted.
            let mut operator = reopen_held(&context, database.path());
            let live = operator.registration.context.payment().epoch();
            assert_eq!(live, u64::from(crash != Crash::BeforeCutover));
            let fenced = !matches!(crash, Crash::AfterAdmission);
            assert_eq!(operator.recovering_epoch().is_some(), fenced, "{crash:?}");
            assert_eq!(operator.pay(2, 3, 1).is_err(), fenced, "{crash:?}");

            // Authentication against the healthy chain releases intake.
            chain.release(&mut operator).await;
            assert!(operator.recovering_epoch().is_none());
            assert!(operator.fault().is_none(), "{crash:?}");
            if let Some((send, entries, accepted)) = receipt {
                let replay = operator.accept_send(send, entries).unwrap().into_accepted();
                assert_eq!(replay.acceptance, accepted.acceptance);
            }
            if !operator.adopted() {
                chain.register(&mut operator).await;
            }
            assert_eq!(operator.pay(2, 3, 1).unwrap().epoch, live, "{crash:?}");

            // Epoch 0 is still held: unadmitted with its close pending, or
            // admitted but not finalized.
            match crash {
                Crash::BeforeCutover => {}
                Crash::AfterAdmission => {
                    let Some(Record::Admitted(admitted)) =
                        chain.control.record(admitted_key(&deployment(), 0)).await
                    else {
                        panic!("epoch 0 lost its admission");
                    };
                    assert!(!admitted.finalized);
                }
                _ => {
                    assert!(
                        chain
                            .control
                            .record(admitted_key(&deployment(), 0))
                            .await
                            .is_none()
                    );
                    assert!(matches!(
                        operator.store.close_outcome(0).unwrap(),
                        StoredCloseOutcome::Pending
                    ));
                    assert_eq!(
                        operator.store.stored_result(0).unwrap().is_some(),
                        crash == Crash::AfterRetention
                    );
                }
            }
        });
    }
}

/// A deployment that faults while the operator is down issues no receipt
/// after the restart. Authentication leaves the fault to the fault path, which
/// fences every unadmitted epoch.
#[test]
fn restart_after_a_fault_during_downtime_issues_no_receipt() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let chain = Chain::new(&context).await;

        // Epoch 0 is cut with its close pending, and epoch 1 registers behind
        // it and pays.
        let deadline = {
            let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
            chain.register(&mut operator).await;
            operator.pay(0, 1, 5).unwrap();
            let (started, resume) = operator.pause_next_close();
            operator.start_close(0).unwrap();
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(resume);
            chain.register(&mut operator).await;
            operator.pay(1, 2, 3).unwrap();
            let Some(Record::Registration(record)) = chain
                .control
                .record(registration_key(&deployment(), 0))
                .await
            else {
                panic!("epoch 0 is not registered");
            };
            record.deadlines.unwrap().0
        };

        // Epoch 0's admission deadline passes while the operator is down.
        let height = chain.control.advance(0).await;
        chain.control.advance(deadline - height + 1).await;
        let faulted = chain.status().await;
        assert!(faulted.hard_faulted);
        assert_eq!((faulted.next_admission, faulted.next_registration), (0, 0));

        // Authentication leaves the faulted chain to the fault path.
        let mut operator = reopen_held(&context, database.path());
        chain.release(&mut operator).await;
        assert_eq!(operator.recovering_epoch(), Some(1));
        assert!(operator.pay(2, 3, 1).is_err());

        // The fault path fences the operator, which still accepts nothing.
        let operator = commonware_utils::sync::Mutex::new(operator);
        let mut client = client::Client::new(
            chain.control.identity(),
            deployment(),
            vec![SocketAddr::from(([127, 0, 0, 1], 9_800))],
            context.child("client"),
        )
        .unwrap();
        service::observe_closes(&context, &mut client, &operator)
            .await
            .unwrap();
        let mut operator = operator.into_inner();
        assert!(operator.fault().is_some());
        assert!(operator.recovering_epoch().is_none());
        assert!(operator.pay(2, 3, 1).is_err());
        assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
    });
}

/// A restarted operator whose adopted live registration is missing from a
/// healthy chain fences itself instead of resuming intake.
#[test]
fn restart_fences_an_adopted_registration_missing_from_the_chain() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let chain = Chain::new(&context).await;
        {
            let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
            operator.adopt_at(0, None).unwrap();
            operator.pay(0, 1, 5).unwrap();
        }
        let mut operator = Operator::open(database.path(), NonZeroUsize::MIN).unwrap();
        let status = chain.status().await;
        assert!(!status.hard_faulted);
        assert_eq!(status.next_registration, 0);
        assert!(
            chain
                .control
                .record(registration_key(&deployment(), 0))
                .await
                .is_none()
        );
        let error = operator.release_recovery(None, &status).unwrap_err();
        assert!(format!("{error:#}").contains("differs from its certified registration"));
        assert!(operator.fault().is_some());
        assert!(operator.recovering_epoch().is_none());
        assert!(operator.pay(0, 1, 1).is_err());
    });
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
        let (admission_deadline, _) = record.deadlines.unwrap();
        let height = chain.control.advance(0).await;
        assert!(height + 3 <= admission_deadline);
        chain.control.advance(admission_deadline - 3 - height).await;

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
        let result = recovered.store.stored_result(0).unwrap().unwrap();
        chain.admit(&result).await;
    });
}

#[test]
fn close_construction_binds_adopted_deadlines() {
    let mut operator = operator();

    observe(
        &mut operator,
        0,
        &[DepositEvent {
            id: Sha256::hash(&[b"long-window-deposit"]),
            account: wallets()[0].public_key(),
            amount: 5,
        }],
    )
    .unwrap();
    let wallet = wallets().remove(0);
    let request = SignedWithdrawal::sign(
        deployment(),
        operator
            .balances
            .as_ref()
            .unwrap()
            .root(operator.registration.context.payment().epoch())
            .unwrap()
            .digest,
        Bytes::copy_from_slice(wallet.public_key().as_ref()),
        amount(5),
        500,
        wallet.signer(),
    );
    operator.apply_withdrawal(request, false).unwrap();

    let admission_deadline = 40;
    let challenge_deadline = admission_deadline + 420;
    let adopted = operator
        .adopt_at(30, Some((admission_deadline, challenge_deadline)))
        .unwrap();
    assert_eq!(adopted.epoch, 0);
    let mut conflicting = adopted.clone();
    conflicting.floors.payouts += 1;
    assert!(operator.adopt_registration(&conflicting).is_err());
    let mut moved = adopted.clone();
    moved.deadlines = Some((admission_deadline + 1, challenge_deadline + 1));
    assert!(operator.adopt_registration(&moved).is_err());
    operator.adopt_registration(&adopted).unwrap();

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

    let retry = operator.apply_withdrawal(request, false).unwrap();
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
    release(&mut recovered);
    let retry = recovered.apply_withdrawal(request, false).unwrap();
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
        .prepare_epoch(data, operator.registration.clone())
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

    let result = operator.complete_prepared(prepared, 44).unwrap();
    assert_eq!(result.withdrawal_total, 95);
    assert_eq!(
        payout_claim(&operator, &result, 0)
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        95
    );
    operator
        .store
        .finish_close(&result, operator.genesis.root())
        .unwrap();
}

#[test]
fn close_can_spend_to_zero_and_retains_a_consumable_zero_output() {
    let mut operator = operator();
    operator.withdraw(0, WithdrawalAction::Close).unwrap();
    operator.pay(0, 1, 100).unwrap();

    let data = operator.store.load_current().unwrap();
    let prepared = operator
        .prepare_epoch(data, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.store.current_liability().unwrap(), 400);

    let result = operator.complete_prepared(prepared, 45).unwrap();
    assert_eq!(result.withdrawal_total, 0);
    assert_eq!(
        payout_claim(&operator, &result, 0)
            .verify::<Sha256>(&result.roots.withdrawal_outputs)
            .unwrap()
            .amount(),
        0
    );
    operator
        .store
        .finish_close(&result, operator.genesis.root())
        .unwrap();
    let retained = operator.store.stored_result(0).unwrap().unwrap();
    assert_eq!(payout_claim(&operator, &retained, 0).output().amount(), 0);
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

async fn prepare_registered_send(
    context: &deterministic::Context,
    chain: &mut client::Client,
    operator: &Mutex<Operator>,
) -> operator_rpc::OperatorRequest {
    let sign = || {
        let operator = operator.lock();
        let (authorization, entries) = operator
            .sign_send(0, &[(operator.wallets[1].public_key(), 1)])
            .unwrap();
        operator_rpc::OperatorRequest::AcceptSend(operator_rpc::AcceptSendRequest {
            authorization,
            entries,
        })
    };
    let request = sign();
    assert!(
        service::prepare_request(context, chain, operator, &request, Timing::DEFAULT)
            .await
            .unwrap()
            .is_none()
    );

    // Registration adopts the certified anchor before the payer signs its accepted send.
    let request = sign();
    assert!(
        service::prepare_request(context, chain, operator, &request, Timing::DEFAULT)
            .await
            .unwrap()
            .is_none()
    );
    request
}

async fn fail_payment_with_buffered_admission(
    context: &deterministic::Context,
    fail_payment: fn(&mut Store),
) -> (Mutex<Operator>, client::Client, SyncSender<()>) {
    let chain = Chain::new(context).await;
    let client = |label| {
        client::Client::new(
            chain.control.identity(),
            deployment(),
            vec![SocketAddr::from(([127, 0, 0, 1], 9_800))],
            context.child(label),
        )
        .unwrap()
    };
    let mut serving = client("serving");
    let operator = Mutex::new(operator());
    let request = prepare_registered_send(context, &mut serving, &operator).await;
    let rpc::Response::Success { body } =
        operator_rpc::handle_decoded(&mut operator.lock(), request)
    else {
        panic!("registered epoch-0 payment failed");
    };
    assert!(matches!(
        operator_rpc::AcceptSendResponse::decode(body).unwrap(),
        operator_rpc::AcceptSendResponse::Accepted(_)
    ));

    // A retained certificate is replayed through the production admission worker.
    // Its successful result stays buffered until the normal service driver collects it.
    let expected = {
        let mut operator = operator.lock();
        let prepared = operator
            .prepare_epoch(
                operator.store.load_current().unwrap(),
                operator.registration.clone(),
            )
            .unwrap();
        rotate_epoch(&mut operator, 0);
        operator.complete_prepared(prepared, 0).unwrap()
    };

    // The close thread replays an admitted result, so its scheduling cannot expire registration.
    client::admit(
        context,
        &mut serving,
        &expected.context,
        AdmitRequest::from(&expected),
    )
    .await
    .unwrap();
    let (started, release) = operator
        .lock()
        .balances
        .as_ref()
        .unwrap()
        .pause_next_catch_up()
        .unwrap();
    let (certifier, mailbox) = node::Certifier::new(
        context.child("admission"),
        node::Config {
            verifier: operator.lock().protocol.verifier(),
            chain: client("admission_client"),
            mailbox_size: NonZeroUsize::new(10).unwrap(),
        },
    );
    let peers = (0..crate::protocol::committee().unwrap().members().len())
        .map(|index| ed25519::PrivateKey::from_seed(index as u64).public_key())
        .collect::<Vec<_>>();
    certifier.start(inert_channel(peers.clone()));
    {
        let mut operator = operator.lock();
        operator.pipeline = Some(node::Pipeline::new(mailbox, &peers, deployment()).unwrap());
        operator.start_next_persisted_close().unwrap();
    }
    for _ in 0..40_000 {
        if operator
            .lock()
            .active_close
            .as_ref()
            .unwrap()
            .thread
            .is_finished()
        {
            break;
        }
        std::thread::yield_now();
        context.sleep(Duration::from_millis(1)).await;
    }
    assert!(
        operator
            .lock()
            .active_close
            .as_ref()
            .unwrap()
            .thread
            .is_finished()
    );
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let admitted = serving.admitted(context, 0).await.unwrap().unwrap();
    assert_eq!(admitted.batch_id, expected.header.batch_id::<Sha256>());
    assert_eq!(admitted.roots, expected.roots);
    assert!(operator.lock().admitted.is_empty());

    // Successor registration requires this actual predecessor admission. The proof
    // worker is held after reading its result and before its next source connection.
    let request = prepare_registered_send(context, &mut serving, &operator).await;
    assert_eq!(operator.lock().registration.context.payment().epoch(), 1);
    let response = {
        let mut operator = operator.lock();
        fail_payment(&mut operator.store);
        operator_rpc::handle_decoded(&mut operator, request)
    };
    let rpc::Response::Error { error } = response else {
        panic!("failed successor payment was acknowledged");
    };
    let error = std::str::from_utf8(&error).unwrap();
    assert!(
        error.contains("payment storage mutation failed")
            || error.contains("payment commit outcome is unknown"),
        "{error}"
    );
    assert!(operator.lock().ensure_store_usable().is_err());
    (operator, serving, release)
}

#[test]
fn foreground_payment_failure_preserves_buffered_close() {
    for fail_payment in [
        Store::fail_next_payment_write as fn(&mut Store),
        Store::fail_next_payment_commit,
    ] {
        deterministic::Runner::default().start(|context| async move {
            let (operator, mut chain, release) =
                fail_payment_with_buffered_admission(&context, fail_payment).await;
            let error = service::observe_closes(&context, &mut chain, &operator)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("SQLite connection is unusable"));

            // Taking ActiveClose precedes the driver's first foreground SQL query.
            // Its presence proves the failed owner was rejected before that query.
            assert!(operator.lock().active_close.is_some());
            assert!(operator.lock().admitted.is_empty());
            release.send(()).unwrap();
            let _ = operator.lock().balances.as_ref().unwrap().catch_up();
        });
    }
}

#[test]
fn foreground_payment_failure_fences_deferred_proof_reads() {
    for fail_payment in [
        Store::fail_next_payment_write as fn(&mut Store),
        Store::fail_next_payment_commit,
    ] {
        deterministic::Runner::default().start(|context| async move {
            let (operator, _, release) =
                fail_payment_with_buffered_admission(&context, fail_payment).await;
            assert!(operator.lock().store.storage_fault().is_some());
            release.send(()).unwrap();
            assert!(
                operator
                    .lock()
                    .balances
                    .as_ref()
                    .unwrap()
                    .catch_up()
                    .is_err()
            );
            assert!(operator.lock().active_close.is_some());
            assert!(operator.lock().admitted.is_empty());
        });
    }
}

#[test]
fn unknown_payment_commit_fences_the_connection() {
    let mut operator = operator();
    operator.fail_next_payment_commit();
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
    assert!(format!("{error:#}").contains("intake commit outcome is unknown"));
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
        .prepare_epoch(data, operator.registration.clone())
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
    assert_eq!(operator.registration.liability, 400);
    assert_eq!(operator.store.current_liability().unwrap(), 400);

    operator.deposit(0, 10).unwrap();
    assert_eq!(operator.registration.liability, 400);
    assert_eq!(operator.store.current_liability().unwrap(), 410);
    operator.pay(0, 1, 5).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 410);
    operator.pay(2, operator.wallet_count(), 25).unwrap();
    assert_eq!(operator.store.current_liability().unwrap(), 410);

    rotate_epoch(&mut operator, 0);
    assert_eq!(operator.registration.liability, 410);
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
        .prepare_epoch(data, operator.registration.clone())
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
        .prepare_epoch(data, operator.registration.clone())
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
            .prepare_epoch(data, operator.registration.clone())
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
        .prepare_epoch(data, operator.registration.clone())
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
    let second = operator.prepare_epoch(frozen, second_registration).unwrap();
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
        operator
            .store
            .predecessor(&operator.wallets[1].public_key())
            .unwrap(),
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
fn queued_closes_finish_in_order() {
    let mut operator = operator();
    let (started, release) = operator.pause_next_close();
    for epoch in 0..8 {
        operator.pay(epoch % 2, (epoch + 1) % 2, 1).unwrap();
        let close = start_current_close(&mut operator).unwrap();
        assert_eq!(close.epoch, epoch as u64);
        if epoch == 0 {
            started.recv_timeout(Duration::from_secs(1)).unwrap();
        } else {
            assert!(close.queued);
        }
    }
    assert!(operator.fault().is_none());

    release.send(()).unwrap();
    let events = operator.wait_for_closes().unwrap();
    assert_eq!(
        events
            .into_iter()
            .map(|event| match event {
                CloseEvent::Finished(close) => close.epoch,
                CloseEvent::Failed { error, .. } => panic!("close failed: {error}"),
            })
            .collect::<Vec<_>>(),
        (0..8).collect::<Vec<_>>()
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
    start_current_close(&mut operator).unwrap();
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    let connection = rusqlite::Connection::open(operator.store.database_path()).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_finalization BEFORE INSERT ON settlements
         BEGIN SELECT RAISE(ABORT, 'injected finalization write failure'); END;",
        )
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
        operator.active_close.take().unwrap().thread.join().unwrap();
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
    release(&mut recovered);
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
fn reopen_rejects_different_genesis_allocations_at_same_liability() {
    let database = TempDatabase::new();
    drop(Operator::open(database.path(), NonZeroUsize::MIN).unwrap());
    let mut replacement = accounts();
    replacement[0].balance -= 1;
    replacement[1].balance += 1;
    let error = match Store::open_configured(database.path(), &identities(), &replacement) {
        Ok(_) => panic!("different genesis allocations reopened"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("wrong genesis allocations"));
}

#[test]
fn certified_result_retention_checks_the_frozen_context_and_predecessor() {
    for epoch in [0, 1] {
        let mut operator = operator();
        if epoch == 1 {
            operator.pay(0, 1, 10).unwrap();
            operator.complete_close(100).unwrap();
        }
        operator.pay(0, 1, 5).unwrap();
        let prepared = operator
            .prepare_epoch(
                operator.store.load_current().unwrap(),
                operator.registration.clone(),
            )
            .unwrap();
        rotate_epoch(&mut operator, epoch);
        let history = operator.validator_history(epoch).unwrap();
        let mut result = operator
            .protocol
            .fixture_complete(&operator.initial_accounts, &history, prepared, 101)
            .unwrap();
        let expected = result.context.clone();
        let bound = expected.encode().slice(
            <EpochContext<Key, Digest> as commonware_codec::FixedSize>::SIZE
                + <StateRoot<Digest> as commonware_codec::FixedSize>::SIZE..,
        );
        let altered = |epoch_context: &EpochContext<Key, Digest>, root: StateRoot<Digest>| {
            commonware_clearing::bajillion::transition::CloseContext::decode(Bytes::from(
                [
                    epoch_context.encode().as_ref(),
                    root.encode().as_ref(),
                    bound.as_ref(),
                ]
                .concat(),
            ))
            .unwrap()
        };
        result.context = altered(
            expected.epoch_context(),
            StateRoot::new(Sha256::hash(&[b"different predecessor"])),
        );
        let error = operator
            .store
            .record_result(&result, operator.genesis.root())
            .unwrap_err();
        assert!(format!("{error:#}").contains("does not extend the retained predecessor"));
        assert!(operator.store.stored_result(epoch).unwrap().is_none());
        result.context = altered(&operator.registration.context, *expected.predecessor_root());
        assert!(
            operator
                .store
                .record_result(&result, operator.genesis.root())
                .is_err()
        );
        assert!(operator.store.stored_result(epoch).unwrap().is_none());
        result.context = expected;
        operator
            .store
            .record_result(&result, operator.genesis.root())
            .unwrap();
        assert_eq!(
            operator
                .store
                .stored_result(epoch)
                .unwrap()
                .unwrap()
                .encode(),
            result.encode()
        );
    }
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
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let result = operator.complete_prepared(prepared, 8).unwrap();
        assert_eq!(result.withdrawal_total, 0);
        chain.admit(&result).await;
        let status = chain.status().await;
        assert_eq!(status.custody, 400);
        assert_eq!(status.claimable, 0);
        operator
            .store
            .finish_close(&result, operator.genesis.root())
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
            operator
                .balances
                .as_ref()
                .unwrap()
                .opening(result.context.payment().epoch() + 1, &eve_identity().key)
                .unwrap()
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
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let first = operator.complete_prepared(prepared, 31).unwrap();
        chain.admit(&first).await;
        let machine_key = crate::chain::state::machine_key(&deployment());
        let Some(Record::Machine(first_machine)) = chain.control.record(machine_key.clone()).await
        else {
            panic!("finalization persists the active machine");
        };
        operator
            .store
            .finish_close(&first, operator.genesis.root())
            .unwrap();

        chain.register(&mut operator).await;
        operator.pay(1, operator.wallet_count(), 20).unwrap();
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let second = operator.complete_prepared(prepared, 32).unwrap();
        chain.admit(&second).await;
        assert_eq!(chain.status().await.claimable, 0);
        assert_eq!(chain.status().await.custody, 400);
        let Some(Record::Machine(second_machine)) = chain.control.record(machine_key).await else {
            panic!("finalization persists the active machine");
        };
        assert_eq!(first_machine.len(), second_machine.len());
        operator
            .store
            .finish_close(&second, operator.genesis.root())
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
            .queue_withdrawal(data.withdrawals[0].request.clone(), first_opening.opening)
            .await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let first = operator.complete_prepared(prepared, 33).unwrap();
        chain.admit(&first).await;
        assert_eq!(chain.status().await.claimable, 25);
        operator
            .store
            .finish_close(&first, operator.genesis.root())
            .unwrap();

        let first_batch = first.header.batch_id::<Sha256>();
        let first_claim = payout_claim(&operator, &first, 0);
        assert_eq!(
            first_claim.position(),
            first.context.predecessor_logs().payouts.operations
        );

        let first_output = released(
            chain
                .claim_withdrawal(&context, first_batch, &first_claim)
                .await,
        );
        assert_eq!(chain.status().await.claimable, 0);

        operator.withdraw(1, amount(30)).unwrap();
        let second_account = operator.wallets[1].public_key();
        let second_opening = operator.withdrawal_opening(&second_account).unwrap();
        let data = operator.store.load_current().unwrap();
        chain
            .queue_withdrawal(data.withdrawals[0].request.clone(), second_opening.opening)
            .await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let second = operator.complete_prepared(prepared, 34).unwrap();
        chain.admit(&second).await;
        assert_eq!(chain.status().await.claimable, 30);

        let second_batch = second.header.batch_id::<Sha256>();
        let second_claim = payout_claim(&operator, &second, 0);
        assert_eq!(
            second_claim.position(),
            second.context.predecessor_logs().payouts.operations
        );
        assert_ne!(second_batch, first_batch);
        let second_output = released(
            chain
                .claim_withdrawal(&context, second_batch, &second_claim)
                .await,
        );
        assert_eq!(chain.status().await.claimable, 0);
        assert_eq!(
            released(
                chain
                    .claim_withdrawal(&context, second_batch, &second_claim)
                    .await
            ),
            second_output
        );

        // Completion identity remains the native position and output across later finalizations.
        assert_eq!(
            released(
                chain
                    .claim_withdrawal(&context, first_batch, &first_claim)
                    .await
            ),
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
        .prepare_epoch(data, operator.registration.clone())
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
        chain.queue_withdrawal(request, opening.opening).await;
        chain.register(&mut operator).await;
        let data = operator.store.load_current().unwrap();
        let prepared = operator
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        let epoch = prepared.epoch();
        rotate_epoch(&mut operator, epoch);
        let result = operator.complete_prepared(prepared, 21).unwrap();
        let batch_id = result.header.batch_id::<Sha256>();
        operator
            .store
            .finish_close(&result, operator.genesis.root())
            .unwrap();

        let retained = operator.store.stored_result(epoch).unwrap().unwrap();
        let evidence = payout_claim(&operator, &retained, 0);
        assert_eq!(evidence.output().amount(), 25);
        assert_eq!(
            evidence.output().destination().as_ref(),
            operator.wallets[0].public_key().as_ref()
        );
        chain.admit(&result).await;
        let release = released(chain.claim_withdrawal(&context, batch_id, &evidence).await);
        assert_eq!(release.amount, 25);
        assert_eq!(
            release.destination.as_ref(),
            operator.wallets[0].public_key().as_ref()
        );
        assert_eq!(release.amount, evidence.output().amount());
        assert_eq!(&release.destination, evidence.output().destination());
        assert_eq!(
            released(chain.claim_withdrawal(&context, batch_id, &evidence).await),
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
            chain.deposit(event).await;
            assert_eq!(chain.observe(&mut operator).await[0].epoch, 0);
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
        let prepared = operator.prepare_epoch(frozen, recovered).unwrap();
        let result = operator.complete_prepared(prepared, 51).unwrap();
        chain.admit(&result).await;
        operator
            .store
            .finish_close(&result, operator.genesis.root())
            .unwrap();
        assert_eq!(operator.payment_head(&account).unwrap().balance, 95);
        assert!(operator.registration.deposits.records().is_empty());
        let claim = payout_claim(&operator, &result, 0);
        let release = released(
            chain
                .claim_withdrawal(&context, result.header.batch_id::<Sha256>(), &claim)
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
            let prepared = operator.prepare_epoch(frozen, recovered).unwrap();
            let result = operator.complete_prepared(prepared, seed).unwrap();
            chain.admit(&result).await;
            operator
                .store
                .finish_close(&result, operator.genesis.root())
                .unwrap();
            result
        }

        let event = DepositEvent {
            id: Sha256::hash(&[b"queued-offset-deposit"]),
            account: account.clone(),
            amount: 7,
        };
        chain.deposit(event).await;
        chain.observe(&mut operator).await;
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
            .queue_withdrawal(queued.clone(), opening.opening)
            .await;
        operator.apply_withdrawal(queued, false).unwrap();
        assert_eq!(operator.payment_head(&account).unwrap().balance, 93);
        assert!(operator.registration.deposits.records().is_empty());
        chain.register(&mut operator).await;
        let second_close = close(&chain, &mut operator, 1, 55).await;

        assert_eq!(operator.payment_head(&account).unwrap().balance, 93);
        assert!(operator.registration.deposits.records().is_empty());
        assert!(!chain.status().await.hard_faulted);

        // Both withdrawal reserves release.
        for result in [&first_close, &second_close] {
            let claim = payout_claim(&operator, result, 0);
            let release = released(
                chain
                    .claim_withdrawal(&context, result.header.batch_id::<Sha256>(), &claim)
                    .await,
            );
            assert_eq!(release.amount, 7);
        }
    });
}

/// A registration pulls only the inbox prefix its operator observed. A deposit
/// the operator has not observed leaves the registration valid and waits in
/// the inbox for the successor.
#[test]
fn unobserved_deposit_waits_past_the_registration() {
    deterministic::Runner::default().start(|context| async move {
        let chain = Chain::new(&context).await;
        let mut operator = operator();
        let account = operator.wallets[0].public_key();

        // The deposit executes before the operator observes it, so the
        // boundary pulls the empty prefix.
        let event = DepositEvent {
            id: Sha256::hash(&[b"hidden-divergence-deposit"]),
            account,
            amount: 7,
        };
        let effect = chain.deposit(event.clone()).await;
        assert_eq!(effect.index, 0);
        operator.withdraw(0, amount(7)).unwrap();
        let register = operator.signed_registration().unwrap();
        assert_eq!(register.end, 0);
        assert_eq!(
            register.deposits_root,
            DepositBatch::<Key>::empty().root::<Sha256>().unwrap()
        );

        // The registration applies and leaves the deposit in the inbox.
        let record = chain
            .try_register(&mut operator)
            .await
            .expect("a registration over the observed prefix was rejected");
        assert_eq!(record.pulled, 0..0);
        operator.adopt_registration(&record).unwrap();
        let status = chain.status().await;
        assert_eq!((status.intake, status.pulled), (1, 0));

        // The published boundary observes the deposit without taking it.
        assert!(chain.observe(&mut operator).await.is_empty());
        assert_eq!(
            operator.store.untaken().unwrap(),
            [(0, Intake::Deposit(event))]
        );
        assert!(operator.registration.deposits.records().is_empty());
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
            register.end,
            &register.deposits_root,
            &register.withdrawals,
            register.fee,
        );
        chain
            .control
            .submit(SettlementTx::RegisterEpoch(register))
            .await;
        assert_eq!(
            chain
                .control
                .record(registration_key(&deployment(), 0))
                .await,
            None
        );

        // The effect-free rejection leaves the epoch slot open: the honest
        // bytes register the same epoch.
        chain.register(&mut operator).await;
    });
}

#[test]
fn withdrawal_reconciliation_requires_the_observed_boundary() {
    let mut operator = operator();
    operator.withdraw(0, amount(7)).unwrap();
    let (observed, discarded) = operator.unregistered_withdrawals().unwrap().unwrap();
    operator.withdraw(1, amount(3)).unwrap();
    let (current, retained) = operator.unregistered_withdrawals().unwrap().unwrap();
    assert_ne!(observed, current);

    operator
        .discard_unregistered_withdrawals(&observed, &discarded)
        .unwrap();
    assert_eq!(
        operator.unregistered_withdrawals().unwrap(),
        Some((current.clone(), retained))
    );
    let first = operator.wallets[0].public_key();
    let second = operator.wallets[1].public_key();
    assert_eq!(operator.payment_head(&first).unwrap().balance, 93);
    assert_eq!(operator.payment_head(&second).unwrap().balance, 97);

    operator
        .discard_unregistered_withdrawals(&current, &discarded)
        .unwrap();
    assert_eq!(operator.payment_head(&first).unwrap().balance, 100);
    assert_eq!(operator.payment_head(&second).unwrap().balance, 97);
    let (_, remaining) = operator.unregistered_withdrawals().unwrap().unwrap();
    assert_eq!(remaining.requests().len(), 1);
    assert_eq!(remaining.requests()[0].account(), &second);
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
            .prepare_epoch(data, operator.registration.clone())
            .unwrap();
        rotate_epoch(&mut operator, 0);
        let result = operator.complete_prepared(prepared, 25).unwrap();
        let mut malformed = AdmitRequest::from(&result);
        malformed.roots.change.root = Sha256::hash(&[b"malformed-change-root"]);
        let epoch = malformed.epoch;

        // A rejected admission is effect-free and must not consume or fence
        // the epoch's registration record.
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
        .prepare_epoch(data, operator.registration.clone())
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
    let retained = operator.store.stored_result(epoch).unwrap().unwrap();
    let evidence = payout_claim(&operator, &retained, 0);
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
        .prepare_epoch(data, operator.registration.clone())
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

/// A deposit past the live boundary's event capacity is observed but not taken, so the
/// boundary, the epoch, and the live liability stay unchanged while the deposit waits.
#[test]
fn deposit_event_capacity_leaves_the_boundary_unchanged() {
    let mut operator = operator();
    for index in 0..1_024 {
        operator
            .deposit(index % operator.wallet_count(), 1)
            .unwrap();
    }
    let epoch = operator.snapshot().unwrap().epoch;
    let liability = operator.store.current_liability().unwrap();
    let context = operator.registration.context.payment().clone();
    let error = match operator.deposit(0, 1) {
        Ok(_) => panic!("deposit event capacity was exceeded"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("did not take the deposit"));
    assert_eq!(operator.snapshot().unwrap().epoch, epoch);
    assert_eq!(operator.store.current_liability().unwrap(), liability);
    assert_eq!(operator.registration.context.payment(), &context);
    assert_eq!(operator.store.untaken().unwrap().len(), 1);
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
            true,
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
        operator.store.predecessor(&recipient.public_key()).unwrap(),
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
    let prepared = operator.prepare_epoch(frozen, registration).unwrap();
    let result = operator.complete_prepared(prepared, 91).unwrap();
    assert_eq!(
        operator
            .balances
            .as_ref()
            .unwrap()
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

    operator.record_admission(&result).unwrap();
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

    assert!(operator.payment_head(&key).is_err());
    operator.wait_for_closes().unwrap();
    release(&mut operator);
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
        payout_claim(&operator, &result, 0)
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
        assert_eq!(
            result.roots.withdrawal_outputs.operations,
            result.context.predecessor_logs().payouts.operations + 1
        );
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
    operator.apply_withdrawal(request.clone(), false).unwrap();
    let closed = operator.complete_close(103).unwrap();
    assert_eq!(closed.withdrawal_total, 90);
    assert_eq!(payout_claim(&operator, &closed, 0).output().amount(), 90);
    assert!(operator.store.current_account(&key).unwrap().is_none());
    assert!(
        operator
            .balances
            .as_ref()
            .unwrap()
            .opening(4, &key)
            .is_err()
    );
    let (send, entries) = operator.sign_send(3, &[(key.clone(), 8)]).unwrap();
    operator.accept_send(send, entries).unwrap();
    assert!(operator.payment_head(&key).is_err());
    assert_eq!(operator.apply_withdrawal(request, false).unwrap().epoch, 3);
    let recreated = operator.complete_close(104).unwrap();
    assert_eq!(recreated.withdrawal_total, 0);
    assert_eq!(
        recreated.roots.withdrawal_outputs.operations,
        recreated.context.predecessor_logs().payouts.operations + 1
    );
    assert_eq!(operator.payment_head(&key).unwrap().balance, 8);
    assert_eq!(operator.store.current_liability().unwrap(), 310);
    assert_eq!(
        operator
            .store
            .stored_result(3)
            .unwrap()
            .unwrap()
            .header
            .batch_id::<Sha256>(),
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
        .prepare_epoch(frozen, operator.registration.clone())
        .unwrap();
    rotate_epoch(&mut operator, 0);
    let result = operator.complete_prepared(prepared, 105).unwrap();
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
    assert!(operator.apply_withdrawal(request, false).is_err());
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
    assert_eq!(result.roots.row_count, 1_025);
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
    observe(&mut operator, 0, &deposits).unwrap();
    let deltas = [
        (Wallet::from_seed("Fresh", 300_000).public_key(), 1),
        (Wallet::from_seed("Fresh", 300_001).public_key(), 1),
    ];
    let (send, entries) = operator.sign_send(0, &deltas).unwrap();
    operator.accept_send(send, entries).unwrap();
    let result = operator.complete_close(107).unwrap();
    assert_eq!(
        result.roots.row_count,
        crate::protocol::MAX_DEPOSIT_EVENTS as u64 + 3
    );
    assert_eq!(result.withdrawal_total, 0);
    assert_eq!(
        operator.store.current_liability().unwrap(),
        400 + crate::protocol::MAX_DEPOSIT_EVENTS as u64
    );
    let encoded = result.encode();
    assert_eq!(
        SettlementResult::decode(encoded).unwrap().roots.row_count,
        result.roots.row_count
    );
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
        true,
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
            operator.store.predecessor(&wallet.public_key()).unwrap(),
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
    assert_eq!(result.roots.row_count, 1_026);
    assert_eq!(operator.store.load_current().unwrap().accounts.len(), 1_024);
    assert_eq!(operator.payment_head(&recipients[0]).unwrap().balance, 1);
    assert_eq!(
        SettlementResult::decode(result.encode())
            .unwrap()
            .roots
            .row_count,
        1_026
    );
}

#[test]
fn virtual_capacity_reuses_a_large_retained_close_after_unknown_commit() {
    let database = TempDatabase::new();
    let (mut operator, wallets) = capacity_genesis(database.path());
    let recipients = capacity_transfers(&mut operator, &wallets, 512);
    operator.fail_next_result_commit();
    start_current_close(&mut operator).unwrap();
    let failed = operator
        .wait_for_closes()
        .err()
        .expect("injected crash completed");
    assert!(format!("{failed:#}").contains("injected"));
    drop(operator);

    let (mut operator, _) = capacity_genesis(database.path());
    operator.wait_for_closes().unwrap();
    release(&mut operator);
    assert_eq!(operator.store.load_current().unwrap().accounts.len(), 1_023);
    assert_eq!(operator.payment_head(&recipients[0]).unwrap().balance, 2);
    let result = operator.store.stored_result(0).unwrap().unwrap();
    assert_eq!(result.roots.row_count, 1_025);
    assert_eq!(
        SettlementResult::decode(result.encode())
            .unwrap()
            .roots
            .row_count,
        1_025
    );
    drop(operator);

    let (operator, _) = capacity_genesis(database.path());

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
            true,
        )
        .unwrap()
    };
    let owner = Wallet::from_seed("Depositor", 600_000);
    let recipient = Wallet::from_seed("Fresh", 600_001).public_key();
    let mut operator = open();
    assert_eq!(operator.store.current_liability().unwrap(), 0);
    assert!(operator.store.load_current().unwrap().accounts.is_empty());
    observe(
        &mut operator,
        0,
        &[DepositEvent {
            id: Sha256::hash(&[b"empty-bootstrap-deposit"]),
            account: owner.public_key(),
            amount: 2,
        }],
    )
    .unwrap();
    operator.complete_close(109).unwrap();
    let empty = Endpoint {
        cumulative_debit: 0,
        seq: 0,
        entries: vec![],
    };
    let (send, entries) = sign_send_at(
        operator.registration.context.payment(),
        operator.store.predecessor(&owner.public_key()).unwrap(),
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

    assert_eq!(operator.store.current_liability().unwrap(), 2);
    assert_eq!(
        operator.payment_head(&owner.public_key()).unwrap().balance,
        1
    );
    assert_eq!(operator.payment_head(&recipient).unwrap().balance, 1);
}
