use super::*;
use crate::chain::state::{Machine, machine_key};

#[test]
fn registry_enumeration_excludes_account_rosters() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("registry_directory"), "registry-directory").await;
        let native = native_for(two_deployments());
        seal_native(&db, 1, &native, &[]).await;
        let expected = native
            .deployments
            .iter()
            .map(|entry| *entry.deployment.digest())
            .collect::<Vec<_>>();
        let directory = registry(&db, &native).await.unwrap();
        assert_eq!(directory.encode(), expected.encode());
        for entry in &native.deployments {
            assert_eq!(
                read(
                    &db,
                    &registry_entry_key(&native.chain_id(), entry.deployment.digest())
                )
                .await,
                Some(Record::RegistryEntry(entry.clone()))
            );
        }

        let wallet = wallets().remove(0);
        let transfer = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"registry-independent-advice"]),
            wallets().remove(1).public_key(),
            1,
            wallet.signer(),
        ));
        let get_calls = || {
            let metrics = commonware_runtime::Metrics::encode(&context);
            let values = metrics
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(' ')?;
                    name.ends_with("_any_get_calls_total")
                        .then(|| value.parse::<u64>().unwrap())
                })
                .collect::<Vec<_>>();
            assert_eq!(values.len(), 1, "one applied QMDB owns these reads");
            values[0]
        };

        let finalized = Finalized::default();
        finalized.record(1, Digest::EMPTY, db.read().await.root(), 1);
        let before = get_calls();
        assert!(matches!(
            crate::chain::state::preflight(&db, &finalized, &native, &Timing::DEFAULT, &transfer)
                .await
                .unwrap(),
            crate::chain::state::Preflight::Eligible { .. }
        ));
        assert_eq!(
            get_calls() - before,
            5,
            "native trials read no deployment rosters or machines"
        );
    });
}

#[test]
fn directory_preserves_accepted_registrations_across_blocks() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("registry_writes"), "registry-writes").await;
        let native = native();
        let owner = operator_signer(0);
        let mut expected = vec![deployment()];
        let mut accepted = Vec::new();
        for height in 1..=2 {
            let request = |id: u64, fee| {
                RegisterDeploymentRequest::sign(
                    native.chain_id(),
                    Sha256::hash(&[&id.to_le_bytes()]),
                    operator_ack_key(0),
                    ed25519::PrivateKey::from_seed(88_888).public_key(),
                    vec![wallets().remove(0).public_key()],
                    1024,
                    fee,
                    &owner,
                )
            };
            let first = request(height * 3, 10);
            let rejected = request(height * 3 + 1, 9);
            let second = request(height * 3 + 2, 10);
            seal_native(
                &db,
                height,
                &native,
                &[
                    first.clone(),
                    rejected.clone(),
                    second.clone(),
                    first.clone(),
                ]
                .map(SettlementTx::RegisterDeployment),
            )
            .await;
            expected.extend([first.deployment_id(), second.deployment_id()]);
            accepted.extend([first, second]);
            assert_eq!(registry(&db, &native).await.unwrap(), expected);
            assert_eq!(
                registry_entry(&db, &native, &rejected.deployment_id())
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(
                read(&db, &machine_key(&rejected.deployment_id())).await,
                None
            );
        }
        seal_native(&db, 3, &native, &[]).await;
        assert_eq!(registry(&db, &native).await.unwrap(), expected);
        for request in accepted {
            assert_eq!(
                registry_entry(&db, &native, &request.deployment_id())
                    .await
                    .unwrap(),
                Some(request.entry(&native).unwrap())
            );
            let Some(Record::Machine(encoded)) =
                read(&db, &machine_key(&request.deployment_id())).await
            else {
                panic!("accepted deployment has a machine");
            };
            assert_eq!(Machine::decode(encoded.clone()).unwrap().encode(), encoded);
        }
        assert_eq!(
            native_balance(&db, &native, &native.fee_recipient)
                .await
                .unwrap(),
            40
        );
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn registration_and_deposit_share_an_atomic_directory_update() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("atomic_registry"), "atomic-registry").await;
        let native = native();
        let owner = operator_signer(0);
        let wallet = wallets().remove(0);
        let request = |salt: &[u8]| {
            RegisterDeploymentRequest::sign(
                native.chain_id(),
                Sha256::hash(&[salt]),
                operator_ack_key(0),
                ed25519::PrivateKey::from_seed(88_888).public_key(),
                vec![wallet.public_key()],
                1024,
                10,
                &owner,
            )
        };
        let abandoned = request(b"abandoned-registry-fork");
        let accepted = request(b"applied-registry-fork");
        let event = DepositEvent {
            id: Sha256::hash(&[b"same-block-native-deposit"]),
            account: wallet.public_key(),
            amount: 7,
        };
        let transactions = |request: &RegisterDeploymentRequest| {
            let registration = SettlementTx::RegisterDeployment(request.clone());
            let deposit = SettlementTx::Deposit(DepositRequest::sign(
                native.chain_id(),
                request.deployment_id(),
                event.clone(),
                wallet.signer(),
            ));
            vec![registration.clone(), deposit.clone(), registration, deposit]
        };
        seal_native(&db, 1, &native, &[]).await;
        let owner_balance = native_balance(&db, &native, &owner.public_key())
            .await
            .unwrap();
        let wallet_balance = native_balance(&db, &native, &wallet.public_key())
            .await
            .unwrap();
        let fork = execute(
            db.new_batches().await,
            Height::new(2),
            2,
            &Timing::DEFAULT,
            &native,
            &transactions(&abandoned),
        )
        .await
        .unwrap();
        assert_eq!(registry(&db, &native).await.unwrap(), vec![deployment()]);
        assert_eq!(
            registry_entry(&db, &native, &abandoned.deployment_id())
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            read(&db, &status_key(&abandoned.deployment_id())).await,
            None
        );
        assert_eq!(
            native_balance(&db, &native, &owner.public_key())
                .await
                .unwrap(),
            owner_balance
        );
        assert_eq!(
            native_balance(&db, &native, &wallet.public_key())
                .await
                .unwrap(),
            wallet_balance
        );
        drop(fork);

        seal_native(&db, 2, &native, &transactions(&accepted)).await;
        let directory = vec![deployment(), accepted.deployment_id()];
        assert_eq!(registry(&db, &native).await.unwrap(), directory);
        assert_eq!(
            registry_entry(&db, &native, &accepted.deployment_id())
                .await
                .unwrap(),
            Some(accepted.entry(&native).unwrap())
        );
        assert_eq!(
            registry_entry(&db, &native, &abandoned.deployment_id())
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            read(&db, &deposit_key(&accepted.deployment_id(), &event.id)).await,
            Some(Record::Deposit(event.clone()))
        );
        assert!(
            matches!(read(&db, &status_key(&accepted.deployment_id())).await, Some(Record::Status(status)) if status.custody == 7)
        );
        assert_eq!(
            native_balance(&db, &native, &owner.public_key())
                .await
                .unwrap(),
            owner_balance - 10
        );
        assert_eq!(
            native_balance(&db, &native, &wallet.public_key())
                .await
                .unwrap(),
            wallet_balance - 7
        );
        assert_eq!(
            native_balance(&db, &native, &native.fee_recipient)
                .await
                .unwrap(),
            10
        );
        assert_supply(&db, &native, &[]).await;
        assert!(db.finalize().await.durable().await);
        drop(db);

        let reopened = open(context.child("registry_reopened"), "atomic-registry").await;
        seal_native(&reopened, 3, &native, &transactions(&accepted)).await;
        assert_eq!(registry(&reopened, &native).await.unwrap(), directory);
        assert_eq!(
            registry_entry(&reopened, &native, &accepted.deployment_id())
                .await
                .unwrap(),
            Some(accepted.entry(&native).unwrap())
        );
        assert_eq!(
            read(
                &reopened,
                &registry_entry_key(&native.chain_id(), &abandoned.deployment_id())
            )
            .await,
            None
        );
        assert_eq!(
            read(&reopened, &status_key(&abandoned.deployment_id())).await,
            None
        );
        assert_eq!(
            read(
                &reopened,
                &deposit_key(&accepted.deployment_id(), &event.id)
            )
            .await,
            Some(Record::Deposit(event))
        );
        assert!(
            matches!(read(&reopened, &status_key(&accepted.deployment_id())).await, Some(Record::Status(status)) if status.custody == 7)
        );
        assert_eq!(
            native_balance(&reopened, &native, &owner.public_key())
                .await
                .unwrap(),
            owner_balance - 10
        );
        assert_eq!(
            native_balance(&reopened, &native, &wallet.public_key())
                .await
                .unwrap(),
            wallet_balance - 7
        );
        assert_eq!(
            native_balance(&reopened, &native, &native.fee_recipient)
                .await
                .unwrap(),
            10
        );
        assert_supply(&reopened, &native, &[]).await;
    });
}

#[test]
fn outsider_deposits_preserve_native_funds_and_finalized_claims() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("outsider_registry"), "outsider-registry").await;
        let (register, admit, claim) = withdrawal_fixture();
        let account = Key::decode(claim.claim.output().destination().clone()).unwrap();
        let wallet = wallets()
            .into_iter()
            .find(|wallet| wallet.public_key() == account)
            .unwrap();
        let mut configured = two_deployments();
        configured[1]
            .accounts
            .retain(|candidate| candidate.key != account);
        let target = *configured[1].digest();
        let target_custody = configured[1]
            .accounts
            .iter()
            .map(|account| account.balance)
            .sum::<u64>();
        let native = native_for(configured);
        seal_native(&db, 1, &native, &[register, admit]).await;
        seal_native(&db, 13, &native, &[]).await;
        assert_eq!(status(&db).await.claimable, 7);
        let initial = native_balance(&db, &native, &account).await.unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"outsider-point-roster"]),
            account: account.clone(),
            amount: 7,
        };
        let deposit = DepositRequest::sign(native.chain_id(), target, event.clone(), wallet.signer());
        assert!(deposit.verify(&native.chain_id()));
        assert!(
            !registry_entry(&db, &native, &target)
                .await
                .unwrap()
                .unwrap()
                .deployment
                .accounts
                .iter()
                .any(|candidate| candidate.key == account)
        );
        let direct = SettlementTx::Deposit(deposit.clone());
        let finalized = Finalized::default();
        finalized.record(13, Digest::EMPTY, db.read().await.root(), 13);
        assert_eq!(
            crate::chain::state::preflight(&db, &finalized, &native, &Timing::DEFAULT, &direct).await.unwrap(),
            crate::chain::state::Preflight::Unavailable
        );
        let release = super::super::state::withdrawal_release_key(
            &deployment(),
            &claim.batch_id,
            claim.claim.position(),
        );
        seal_native(
            &db,
            14,
            &native,
            &[
                direct,
                SettlementTx::ClaimDeposit(ClaimDepositRequest {
                    claim: FinalizedClaim::Withdrawal(claim.clone()),
                    deposit,
                }),
            ],
        )
        .await;
        assert_eq!(read(&db, &deposit_key(&target, &event.id)).await, None);
        assert_eq!(read(&db, &release).await, None);
        assert_eq!(status(&db).await.claimable, 7);
        assert_eq!(
            native_balance(&db, &native, &account).await.unwrap(),
            initial
        );
        assert!(
            matches!(read(&db, &status_key(&target)).await, Some(Record::Status(status)) if status.custody == target_custody)
        );
        assert_supply(&db, &native, &[]).await;
        seal_native(&db, 15, &native, &[SettlementTx::ClaimWithdrawal(claim)]).await;
        assert!(matches!(
            read(&db, &release).await,
            Some(Record::WithdrawalRelease(_))
        ));
        assert_eq!(status(&db).await.claimable, 0);
        assert_eq!(
            native_balance(&db, &native, &account).await.unwrap(),
            initial + 7
        );
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn untouched_registered_deployment_expires_without_transactions() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("untouched_clock"), "untouched-clock").await;
        let native = native_for(two_deployments());
        seal_native(&db, 1, &native, &[empty_register_tx()]).await;
        let registration = registration(&db).await;
        seal_native(&db, registration.admission_deadline + 1, &native, &[]).await;
        assert!(status(&db).await.hard_faulted);
        assert!(matches!(
            read(&db, &fault_key(&deployment())).await,
            Some(Record::Fault(_))
        ));
        let other = native.deployments[1].deployment.digest();
        assert!(
            matches!(read(&db, &status_key(other)).await, Some(Record::Status(status)) if !status.hard_faulted && status.custody == 400)
        );
        for entry in &native.deployments {
            assert_eq!(
                registry_entry(&db, &native, entry.deployment.digest())
                    .await
                    .unwrap(),
                Some(entry.clone())
            );
        }
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn runtime_registration_uses_the_trusted_empty_qmdb_head() {
    let native = native();
    let wallet = wallets().remove(0);
    let request = RegisterDeploymentRequest::sign(
        native.chain_id(),
        Sha256::hash(&[b"empty-head-contract"]),
        operator_ack_key(0),
        ed25519::PrivateKey::from_seed(99).public_key(),
        vec![wallet.public_key()],
        1024,
        10,
        &operator_signer(0),
    );
    let entry = request.entry(&native).unwrap();
    assert_eq!(entry.deployment.genesis().root(), native.empty_root);
    assert_eq!(
        entry.deployment.genesis().operations(),
        native.empty_operations
    );
    assert_eq!(entry.deployment.genesis().liability(), 0);
    assert!(
        crate::protocol::genesis_balances(&entry.deployment)
            .unwrap()
            .is_empty()
    );
    assert_eq!(entry.deployment.accounts[0].key, wallet.public_key());
    assert_eq!(RegistryEntry::decode(entry.encode()).unwrap(), entry);
    let encoded = entry.encode();
    for end in 0..encoded.len() {
        assert!(RegistryEntry::decode(encoded.slice(..end)).is_err());
    }
    let mut duplicate = request;
    duplicate.accounts.push(wallet.public_key());
    assert!(duplicate.entry(&native).is_err());
    let mut rebound = entry.deployment.clone();
    rebound.rebind(Sha256::hash(&[b"another-full-identity"]));
    assert_ne!(rebound.digest(), entry.deployment.digest());
    assert_eq!(rebound.genesis(), entry.deployment.genesis());
}
