use super::*;
use crate::chain::state::{Preflight, ProofAction, preflight};

async fn apply(
    db: &Database<deterministic::Context>,
    finalized: &Finalized,
    native: &NativeGenesis,
    height: u64,
    txs: &[SettlementTx],
) {
    let (root, _) = seal_native(db, height, native, txs).await;
    finalized.record(height, Sha256::hash(&[&height.to_le_bytes()]), root, height);
}

async fn trial(
    db: &Database<deterministic::Context>,
    finalized: &Finalized,
    native: &NativeGenesis,
    tx: &SettlementTx,
) -> Preflight {
    let root = db.read().await.root();
    let tip = finalized
        .latest()
        .map(|tip| (tip.height, tip.digest, tip.root, tip.timestamp));
    let result = preflight(db, finalized, native, &Timing::DEFAULT, tx)
        .await
        .unwrap();
    assert_eq!(db.read().await.root(), root, "a trial cannot commit writes");
    assert_eq!(
        finalized
            .latest()
            .map(|tip| (tip.height, tip.digest, tip.root, tip.timestamp)),
        tip,
        "a trial cannot advance finality"
    );
    result
}

#[test]
fn native_preflight_requires_a_coherent_tip_and_never_spends() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("preflight_native"), "preflight-native").await;
        let native = native();
        let finalized = Finalized::default();
        let sender = wallets().remove(0);
        let receiver = wallets().remove(1).public_key();
        let request = NativeTransferRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"preflight-transfer"]),
            receiver.clone(),
            7,
            sender.signer(),
        );
        let tx = SettlementTx::NativeTransfer(request.clone());
        assert_eq!(
            trial(&db, &finalized, &native, &tx).await,
            Preflight::Unavailable
        );
        apply(&db, &finalized, &native, 1, &[]).await;
        let initial = native_balance(&db, &native, &sender.public_key())
            .await
            .unwrap();
        let root = db.read().await.root();
        finalized.record(1, Digest::EMPTY, Digest::EMPTY, 1);
        assert_eq!(
            trial(&db, &finalized, &native, &tx).await,
            Preflight::Unavailable
        );
        finalized.record(1, Digest::EMPTY, root, 1);
        for _ in 0..2 {
            assert!(matches!(
                trial(&db, &finalized, &native, &tx).await,
                Preflight::Eligible { .. }
            ));
        }
        for amount in [0, initial + 1] {
            let unfunded = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
                native.chain_id(),
                Sha256::hash(&[&amount.to_le_bytes()]),
                receiver.clone(),
                amount,
                sender.signer(),
            ));
            assert_eq!(
                trial(&db, &finalized, &native, &unfunded).await,
                Preflight::Unavailable
            );
        }
        let stranger = crate::protocol::Wallet::from_seed("unfunded", 9_999);
        let unfunded = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"missing-native-account"]),
            receiver.clone(),
            1,
            stranger.signer(),
        ));
        assert_eq!(
            trial(&db, &finalized, &native, &unfunded).await,
            Preflight::Unavailable
        );
        let mut invalid = request;
        invalid.amount += 1;
        assert_eq!(
            trial(
                &db,
                &finalized,
                &native,
                &SettlementTx::NativeTransfer(invalid.clone())
            )
            .await,
            Preflight::Unavailable
        );
        assert_eq!(
            native_balance(&db, &native, &sender.public_key())
                .await
                .unwrap(),
            initial
        );
        apply(
            &db,
            &finalized,
            &native,
            2,
            &[SettlementTx::NativeTransfer(invalid), tx.clone()],
        )
        .await;
        assert_eq!(
            native_balance(&db, &native, &sender.public_key())
                .await
                .unwrap(),
            initial - 7
        );
        assert_eq!(
            trial(&db, &finalized, &native, &tx).await,
            Preflight::Unavailable
        );
        assert_supply(&db, &native, &[]).await;
        assert!(db.finalize().await.durable().await);
        drop(db);
        let reopened = open(context.child("preflight_reopened"), "preflight-native").await;
        assert_eq!(
            trial(&reopened, &finalized, &native, &tx).await,
            Preflight::Unavailable
        );
        assert_eq!(
            native_balance(&reopened, &native, &sender.public_key())
                .await
                .unwrap(),
            initial - 7
        );
        assert_supply(&reopened, &native, &[]).await;
    });
}

#[test]
fn preflight_registration_and_deposit_follow_canonical_membership() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("preflight_registry"), "preflight-registry").await;
        let native = native();
        let finalized = Finalized::default();
        apply(&db, &finalized, &native, 1, &[]).await;
        let wallet = wallets().remove(0);
        let request = RegisterDeploymentRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"preflight-registration"]),
            operator_ack_key(0),
            ed25519::PrivateKey::from_seed(98).public_key(),
            vec![wallet.public_key()],
            1024,
            10,
            &operator_signer(0),
        );
        let target = request.deployment_id();
        let registration = SettlementTx::RegisterDeployment(request);
        let event = DepositEvent {
            id: Sha256::hash(&[b"preflight-deposit"]),
            account: wallet.public_key(),
            amount: 7,
        };
        let deposit = SettlementTx::Deposit(DepositRequest::sign(
            native.chain_id(),
            target,
            event.clone(),
            wallet.signer(),
        ));
        assert!(matches!(
            trial(&db, &finalized, &native, &registration).await,
            Preflight::Eligible { .. }
        ));
        assert_eq!(
            trial(&db, &finalized, &native, &deposit).await,
            Preflight::Unavailable
        );
        assert_eq!(registry_entry(&db, &native, &target).await.unwrap(), None);
        apply(
            &db,
            &finalized,
            &native,
            2,
            std::slice::from_ref(&registration),
        )
        .await;
        assert_eq!(
            trial(&db, &finalized, &native, &registration).await,
            Preflight::Unavailable
        );
        assert!(matches!(
            trial(&db, &finalized, &native, &deposit).await,
            Preflight::Eligible { .. }
        ));
        assert_eq!(read(&db, &deposit_key(&target, &event.id)).await, None);
        apply(&db, &finalized, &native, 3, std::slice::from_ref(&deposit)).await;
        assert_eq!(
            trial(&db, &finalized, &native, &deposit).await,
            Preflight::Unavailable
        );
        assert_eq!(
            read(&db, &deposit_key(&target, &event.id)).await,
            Some(Record::Deposit(event))
        );
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn preflight_uses_the_current_height_and_adjudicates_challenges() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("preflight_fault"), "preflight-fault").await;
        let native = native();
        let finalized = Finalized::default();
        let fixture = epoch_fixture();
        apply(
            &db,
            &finalized,
            &native,
            1,
            &[fixture.deposit_tx.clone(), fixture.register_tx.clone()],
        )
        .await;
        apply(&db, &finalized, &native, 11, &[]).await;
        assert!(!status(&db).await.hard_faulted);
        assert!(matches!(
            trial(&db, &finalized, &native, &fixture.admit_tx).await,
            Preflight::Eligible { .. }
        ));
        // The admission deadline is inclusive; preflight does not execute the next block's clock.
        assert!(!status(&db).await.hard_faulted);
        apply(
            &db,
            &finalized,
            &native,
            12,
            std::slice::from_ref(&fixture.admit_tx),
        )
        .await;
        assert!(status(&db).await.hard_faulted);
        assert_eq!(
            trial(&db, &finalized, &native, &fixture.admit_tx).await,
            Preflight::Unavailable
        );

        let db = open(context.child("preflight_challenge"), "preflight-challenge").await;
        let finalized = Finalized::default();
        apply(
            &db,
            &finalized,
            &native,
            1,
            &[fixture.deposit_tx.clone(), fixture.register_tx.clone()],
        )
        .await;
        apply(
            &db,
            &finalized,
            &native,
            2,
            std::slice::from_ref(&fixture.admit_tx),
        )
        .await;
        assert_eq!(
            trial(&db, &finalized, &native, &fixture.admit_tx).await,
            Preflight::Unavailable
        );
        let challenge = |amounts| {
            SettlementTx::Challenge(ChallengeRequest {
                deployment: deployment(),
                batch_id: fixture.result.finalized.batch_id,
                evidence: ack_fork(&fixture.result, &fixture.protocol, amounts).encode(),
            })
        };
        let bogus = SettlementTx::Challenge(ChallengeRequest {
            deployment: deployment(),
            batch_id: fixture.result.finalized.batch_id,
            evidence: Bytes::new(),
        });
        assert_eq!(
            trial(&db, &finalized, &native, &bogus).await,
            Preflight::Unavailable
        );
        let first = challenge((2, 3));
        let alternative = challenge((4, 5));
        let expected = Preflight::Eligible {
            action: Some(ProofAction::Challenge {
                deployment: deployment(),
                batch_id: fixture.result.finalized.batch_id,
            }),
        };
        assert_eq!(trial(&db, &finalized, &native, &first).await, expected);
        assert_eq!(
            trial(&db, &finalized, &native, &alternative).await,
            expected
        );
        assert!(!status(&db).await.hard_faulted);
        apply(&db, &finalized, &native, 3, &[bogus, first]).await;
        assert!(status(&db).await.hard_faulted);
        let begin = SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
            deployment: deployment(),
        });
        assert!(matches!(
            trial(&db, &finalized, &native, &begin).await,
            Preflight::Eligible { .. }
        ));
        apply(&db, &finalized, &native, 4, std::slice::from_ref(&begin)).await;
        assert_eq!(
            trial(&db, &finalized, &native, &begin).await,
            Preflight::Unavailable
        );
        let account = &fixture.state.accounts[0].key;
        let claim = SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
            deployment: deployment(),
            opening: fixture.state.opening(account).unwrap(),
        });
        assert!(matches!(
            trial(&db, &finalized, &native, &claim).await,
            Preflight::Eligible { .. }
        ));
        assert_eq!(
            read(&db, &hard_fault_key(&deployment(), account)).await,
            None
        );
        apply(&db, &finalized, &native, 5, std::slice::from_ref(&claim)).await;
        assert_eq!(
            trial(&db, &finalized, &native, &claim).await,
            Preflight::Unavailable
        );
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn preflight_compound_claim_uses_the_source_identity_without_consuming_it() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("preflight_claim"), "preflight-claim").await;
        let native = native_for(two_deployments());
        let finalized = Finalized::default();
        let (register, admit, claim) = withdrawal_fixture();
        apply(&db, &finalized, &native, 1, &[register, admit]).await;
        apply(&db, &finalized, &native, 13, &[]).await;
        let account = Key::decode(claim.claim.output().destination().clone()).unwrap();
        let wallet = wallets()
            .into_iter()
            .find(|wallet| wallet.public_key() == account)
            .unwrap();
        let target = *native.deployments[1].deployment.digest();
        let make = |target| {
            SettlementTx::ClaimDeposit(ClaimDepositRequest {
                claim: FinalizedClaim::Withdrawal(claim.clone()),
                deposit: DepositRequest::sign(
                    native.chain_id(),
                    target,
                    DepositEvent {
                        id: Sha256::hash(&[b"preflight-compound"]),
                        account: account.clone(),
                        amount: 7,
                    },
                    wallet.signer(),
                ),
            })
        };
        let release = crate::chain::state::withdrawal_release_key(
            &deployment(),
            &claim.batch_id,
            claim.claim.position(),
        );
        let expected = Preflight::Eligible {
            action: Some(ProofAction::Effect(release.clone())),
        };
        let direct = SettlementTx::ClaimWithdrawal(claim.clone());
        assert_eq!(trial(&db, &finalized, &native, &direct).await, expected);
        let compound = make(target);
        assert_eq!(trial(&db, &finalized, &native, &compound).await, expected);
        assert_eq!(
            trial(
                &db,
                &finalized,
                &native,
                &make(Sha256::hash(&[b"unknown-target"]))
            )
            .await,
            Preflight::Unavailable
        );
        assert_eq!(read(&db, &release).await, None);
        assert_eq!(status(&db).await.claimable, 7);
        apply(
            &db,
            &finalized,
            &native,
            14,
            std::slice::from_ref(&compound),
        )
        .await;
        for tx in [direct, compound] {
            assert_eq!(
                trial(&db, &finalized, &native, &tx).await,
                Preflight::Unavailable
            );
        }
        assert_eq!(status(&db).await.claimable, 0);
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn same_deployment_claim_deposit_preserves_both_machine_effects() {
    deterministic::Runner::default().start(|context| async move {
        for blocked in [false, true] {
            let prefix = if blocked { "same_blocked" } else { "same_open" };
            let db = open(context.child(prefix), prefix).await;
            let native = native();
            let finalized = Finalized::default();
            let (register, admit, claim) = withdrawal_fixture();
            apply(&db, &finalized, &native, 1, &[register, admit]).await;
            apply(&db, &finalized, &native, 13, &[]).await;
            let account = Key::decode(claim.claim.output().destination().clone()).unwrap();
            let wallet = wallets()
                .into_iter()
                .find(|wallet| wallet.public_key() == account)
                .unwrap();
            let initial = native_balance(&db, &native, &account).await.unwrap();
            if blocked {
                let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
                let root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
                let withdrawals = WithdrawalBatch::empty();
                let register = RegisterEpochRequest {
                    deployment: deployment(),
                    epoch: 1,
                    predecessor_liability: 393,
                    deposits_root: root,
                    staged_root: root,
                    withdrawals: withdrawals.clone(),
                    openings: Vec::new(),
                    fee: 4096,
                    signature: protocol.sign_chain_registration(
                        1,
                        393,
                        &root,
                        &root,
                        &withdrawals,
                        4096,
                    ),
                };
                apply(
                    &db,
                    &finalized,
                    &native,
                    14,
                    &[SettlementTx::RegisterEpoch(register)],
                )
                .await;
            }
            let event = DepositEvent {
                id: Sha256::hash(&[prefix.as_bytes()]),
                account: account.clone(),
                amount: 7,
            };
            let compound = SettlementTx::ClaimDeposit(ClaimDepositRequest {
                claim: FinalizedClaim::Withdrawal(claim.clone()),
                deposit: DepositRequest::sign(
                    native.chain_id(),
                    deployment(),
                    event.clone(),
                    wallet.signer(),
                ),
            });
            let direct = SettlementTx::ClaimWithdrawal(claim.clone());
            let release = crate::chain::state::withdrawal_release_key(
                &deployment(),
                &claim.batch_id,
                claim.claim.position(),
            );
            let eligibility = trial(&db, &finalized, &native, &compound).await;
            assert_eq!(
                eligibility,
                if blocked {
                    Preflight::Unavailable
                } else {
                    Preflight::Eligible {
                        action: Some(ProofAction::Effect(release.clone())),
                    }
                }
            );
            let height = if blocked { 15 } else { 14 };
            apply(
                &db,
                &finalized,
                &native,
                height,
                std::slice::from_ref(&compound),
            )
            .await;
            assert_eq!(
                native_balance(&db, &native, &account).await.unwrap(),
                initial
            );
            assert_eq!(
                read(&db, &deposit_key(&deployment(), &event.id)).await,
                if blocked {
                    None
                } else {
                    Some(Record::Deposit(event))
                }
            );
            assert_eq!(status(&db).await.claimable, if blocked { 7 } else { 0 });
            assert_eq!(status(&db).await.custody, if blocked { 393 } else { 400 });
            assert_eq!(read(&db, &release).await.is_some(), !blocked);
            apply(&db, &finalized, &native, height + 1, &[direct, compound]).await;
            assert_eq!(
                native_balance(&db, &native, &account).await.unwrap(),
                initial + if blocked { 7 } else { 0 }
            );
            assert_eq!(status(&db).await.claimable, 0);
            assert_supply(&db, &native, &[]).await;
        }
    });
}
