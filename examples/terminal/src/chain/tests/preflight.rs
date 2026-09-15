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
                batch_id: fixture.result.header.batch_id::<Sha256>(),
                evidence: ack_fork(&fixture.result, &fixture.protocol, amounts).encode(),
            })
        };
        let bogus = SettlementTx::Challenge(ChallengeRequest {
            deployment: deployment(),
            batch_id: fixture.result.header.batch_id::<Sha256>(),
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
                batch_id: fixture.result.header.batch_id::<Sha256>(),
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
                claim: claim.clone(),
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
        let action = ProofAction::Payout {
            deployment: deployment(),
            index: claim.claim.position(),
        };
        let expected = Preflight::Eligible {
            action: Some(action.clone()),
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
        assert!(matches!(
            read(&db, &unclaimed_key(&deployment(), claim.start)).await,
            Some(Record::Unclaimed(_))
        ));
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

                    withdrawals: withdrawals.clone(),
                    openings: Vec::new(),
                    fee: 4096,
                    signature: protocol.sign_chain_registration(1, 393, &root, &withdrawals, 4096),
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
                claim: claim.clone(),
                deposit: DepositRequest::sign(
                    native.chain_id(),
                    deployment(),
                    event.clone(),
                    wallet.signer(),
                ),
            });
            let direct = SettlementTx::ClaimWithdrawal(claim.clone());
            let action = ProofAction::Payout {
                deployment: deployment(),
                index: claim.claim.position(),
            };
            let eligibility = trial(&db, &finalized, &native, &compound).await;
            assert_eq!(
                eligibility,
                if blocked {
                    Preflight::Unavailable
                } else {
                    Preflight::Eligible {
                        action: Some(action.clone()),
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
            assert_eq!(
                read(&db, &unclaimed_key(&deployment(), claim.start))
                    .await
                    .is_some(),
                blocked
            );
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

#[test]
fn withdrawal_preflight_survives_active_epochs_and_new_admissions() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(
            context.child("preflight_withdrawal"),
            "preflight-withdrawal",
        )
        .await;
        let native = native();
        let finalized = Finalized::default();
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let genesis = genesis_cache();
        let wallet = wallets().remove(3);
        let account = wallet.public_key();
        let request = SignedWithdrawal::sign(
            deployment(),
            genesis.root().digest,
            account.encode(),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            50,
            wallet.signer(),
        );
        let queue = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
            request: request.clone(),
            opening: genesis.opening(&account).unwrap(),
        });
        let encoded = queue.encode();
        let first = close_fixture(
            native.chain_id(),
            &protocol,
            0,
            genesis.clone(),
            b"preflight-withdrawal-first",
            11,
            12,
        );
        apply(
            &db,
            &finalized,
            &native,
            1,
            &[first.deposit_tx, first.register_tx],
        )
        .await;
        assert!(
            matches!(
                trial(&db, &finalized, &native, &queue).await,
                Preflight::Eligible { .. }
            ),
            "an active epoch cannot block escalation"
        );
        apply(&db, &finalized, &native, 2, &[first.admit_tx]).await;
        assert!(
            matches!(
                trial(&db, &finalized, &native, &queue).await,
                Preflight::Eligible { .. }
            ),
            "admission cannot stale the finalized-root opening"
        );

        let second = close_fixture(
            native.chain_id(),
            &protocol,
            1,
            first.successor,
            b"preflight-withdrawal-second",
            13,
            14,
        );
        apply(
            &db,
            &finalized,
            &native,
            3,
            &[second.deposit_tx, second.register_tx],
        )
        .await;
        let anchor = read(&db, &anchor_key(&deployment(), 1)).await;
        assert!(matches!(
            trial(&db, &finalized, &native, &queue).await,
            Preflight::Eligible { .. }
        ));
        assert_eq!(queue.encode(), encoded);
        apply(&db, &finalized, &native, 4, &[queue, second.admit_tx]).await;
        assert_eq!(read(&db, &anchor_key(&deployment(), 1)).await, anchor);
        assert_eq!(status(&db).await.state_root, genesis.root());
        assert_eq!(
            read(&db, &withdrawal_key(&deployment(), &account)).await,
            Some(Record::Withdrawal(request.clone()))
        );
        assert!(db.finalize().await.durable().await);
        drop(db);
        let db = open(
            context.child("preflight_withdrawal_restart"),
            "preflight-withdrawal",
        )
        .await;

        let state = second.successor;
        let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
        let deposits = DepositBatch::empty();
        let root = deposits.root::<Sha256>().unwrap();
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 2,
            predecessor_liability: state.liability(),
            deposits_root: root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            fee: 4096,
            signature: protocol.sign_chain_registration(
                2,
                state.liability(),
                &root,
                &withdrawals,
                4096,
            ),
        });
        let SettlementTx::RegisterEpoch(mut omitted) = register.clone() else {
            unreachable!();
        };
        omitted.withdrawals = WithdrawalBatch::empty();
        omitted.openings.clear();
        omitted.signature = protocol.sign_chain_registration(
            2,
            state.liability(),
            &root,
            &omitted.withdrawals,
            4096,
        );
        assert_eq!(
            trial(
                &db,
                &finalized,
                &native,
                &SettlementTx::RegisterEpoch(omitted)
            )
            .await,
            Preflight::Unavailable,
            "admission and restart must preserve the exact queued obligation",
        );
        assert!(matches!(
            trial(&db, &finalized, &native, &register).await,
            Preflight::Eligible { .. }
        ));
        let registration = protocol
            .registration_at(2, deposits, withdrawals, state.liability(), 15, 16)
            .unwrap();
        let balance_state = replay_state(
            context.child("preflight_withdrawal_validator"),
            crate::protocol::state_config(
                "preflight-withdrawal-validator",
                &context,
                protocol.strategy().clone(),
            ),
            &state.history,
        )
        .await;
        let (result, candidate) = protocol
            .complete(
                protocol.prepare(registration, Vec::new()).unwrap(),
                &balance_state,
                &mut TestRng::new(191),
            )
            .await
            .unwrap();
        let payout_position = result.context.predecessor_logs().payouts.operations;
        let balance_state = balance_state.apply(candidate).await.unwrap();
        let output = balance_state
            .logs()
            .payout_at(payout_position)
            .await
            .unwrap();
        let (opening, _) = balance_state
            .logs()
            .payout_opening(
                &result.roots.withdrawal_outputs,
                payout_position,
                NonZeroU64::MIN,
            )
            .await
            .unwrap();
        apply(
            &db,
            &finalized,
            &native,
            5,
            &[register, SettlementTx::Admit(AdmitRequest::from(&result))],
        )
        .await;
        for height in [13, 15, 17] {
            apply(&db, &finalized, &native, height, &[]).await;
        }
        assert_eq!(status(&db).await.last_finalized, Some(2));
        let initial = native_balance(&db, &native, &account).await.unwrap();
        let claim = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            start: payout_position,
            claim: WithdrawalClaim::new(output, opening),
        });
        apply(&db, &finalized, &native, 18, &[claim.clone(), claim]).await;
        assert_eq!(
            native_balance(&db, &native, &account).await.unwrap(),
            initial + 7
        );
        assert_supply(&db, &native, &[]).await;
    });
}

#[test]
fn queued_withdrawal_carries_zero_after_accepted_spending() {
    for (spent, action) in [
        (95, WithdrawalAction::Amount(NonZeroU64::new(7).unwrap())),
        (100, WithdrawalAction::Close),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let db = open(context.child("queued_zero"), "queued-zero").await;
            let native = native();
            let finalized = Finalized::default();
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let genesis = genesis_cache();
            let payer = wallets().remove(0);
            let recipient = wallets().remove(1);
            let account = payer.public_key();
            let request = SignedWithdrawal::sign(
                deployment(),
                genesis.root().digest,
                account.encode(),
                action,
                50,
                payer.signer(),
            );
            let queue = SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: request.clone(),
                opening: genesis.opening(&account).unwrap(),
            });
            let deposits = DepositBatch::empty();
            let deposits_root = deposits.root::<Sha256>().unwrap();
            let empty = WithdrawalBatch::empty();
            let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
                deployment: deployment(),
                epoch: 0,
                predecessor_liability: 400,
                deposits_root,
                withdrawals: empty.clone(),
                openings: Vec::new(),
                fee: 4096,
                signature: protocol.sign_chain_registration(0, 400, &deposits_root, &empty, 4096),
            });
            apply(&db, &finalized, &native, 1, &[register]).await;
            let registration = protocol
                .registration_at(0, deposits.clone(), empty, 400, 11, 12)
                .unwrap();
            let vector = OutVector::new(
                0,
                account.clone(),
                vec![OutEntry {
                    recipient: recipient.public_key(),
                    cumulative: spent,
                    count: 1,
                }],
            )
            .unwrap();
            let body = VectorSendBody::new(
                registration.context.payment(),
                account.clone(),
                1,
                spent,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            let terminal = Terminal {
                operator_signature: protocol.sign_ack_aggregate(&body),
                authorization: SendAuthorization::sign(body, payer.signer()),
                vector,
            };
            let balances = replay_state(
                context.child("queued_zero_validator"),
                crate::protocol::state_config(
                    "queued-zero-validator",
                    &context,
                    protocol.strategy().clone(),
                ),
                &genesis.history,
            )
            .await;
            let (paid, candidate) = protocol
                .complete(
                    protocol.prepare(registration, vec![terminal]).unwrap(),
                    &balances,
                    &mut TestRng::new(201),
                )
                .await
                .unwrap();
            let balances = balances.apply(candidate).await.unwrap();
            assert!(matches!(
                trial(&db, &finalized, &native, &queue).await,
                Preflight::Eligible { .. }
            ));
            apply(
                &db,
                &finalized,
                &native,
                2,
                &[queue, SettlementTx::Admit(AdmitRequest::from(&paid))],
            )
            .await;
            assert_eq!(
                balances
                    .state()
                    .get(&account_key(&account).unwrap())
                    .await
                    .unwrap(),
                NonZeroU64::new(100 - spent)
            );
            assert_eq!(
                balances
                    .state()
                    .opening(recipient.public_key())
                    .await
                    .unwrap()
                    .balance
                    .get(),
                100 + spent
            );

            let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
            let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
                deployment: deployment(),
                epoch: 1,
                predecessor_liability: 400,
                deposits_root,
                withdrawals: withdrawals.clone(),
                openings: Vec::new(),
                fee: 4096,
                signature: protocol.sign_chain_registration(
                    1,
                    400,
                    &deposits_root,
                    &withdrawals,
                    4096,
                ),
            });
            assert!(
                matches!(
                    trial(&db, &finalized, &native, &register).await,
                    Preflight::Eligible { .. }
                ),
                "queued requests need no fresh predecessor proof"
            );
            let registration = protocol
                .registration_at(1, deposits, withdrawals, 400, 13, 14)
                .unwrap();
            let (carried, candidate) = protocol
                .complete(
                    protocol.prepare(registration, Vec::new()).unwrap(),
                    &balances,
                    &mut TestRng::new(202),
                )
                .await
                .unwrap();
            assert_eq!(carried.withdrawal_total, 0);
            let payout_position = carried.context.predecessor_logs().payouts.operations;
            let balances = balances.apply(candidate).await.unwrap();
            let output = balances.logs().payout_at(payout_position).await.unwrap();
            assert_eq!(output.amount(), 0);
            let (opening, _) = balances
                .logs()
                .payout_opening(
                    &carried.roots.withdrawal_outputs,
                    payout_position,
                    NonZeroU64::MIN,
                )
                .await
                .unwrap();
            assert_eq!(
                balances
                    .state()
                    .get(&account_key(&account).unwrap())
                    .await
                    .unwrap(),
                NonZeroU64::new(100 - spent)
            );
            assert_eq!(
                balances
                    .state()
                    .opening(recipient.public_key())
                    .await
                    .unwrap()
                    .balance
                    .get(),
                100 + spent
            );
            apply(
                &db,
                &finalized,
                &native,
                3,
                &[register, SettlementTx::Admit(AdmitRequest::from(&carried))],
            )
            .await;
            for height in [13, 15] {
                apply(&db, &finalized, &native, height, &[]).await;
            }
            assert_eq!(status(&db).await.last_finalized, Some(1));
            assert_eq!(status(&db).await.state_root, carried.roots.successor);
            assert_eq!(status(&db).await.claimable, 0);
            let initial = native_balance(&db, &native, &account).await.unwrap();
            let claim = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                deployment: deployment(),
                start: payout_position,
                claim: WithdrawalClaim::new(output, opening),
            });
            apply(&db, &finalized, &native, 16, &[claim.clone(), claim]).await;
            assert_eq!(
                native_balance(&db, &native, &account).await.unwrap(),
                initial
            );
            assert_eq!(
                read(
                    &db,
                    &unclaimed_key(
                        &deployment(),
                        carried.context.predecessor_logs().payouts.operations
                    )
                )
                .await,
                None
            );
            assert_eq!(status(&db).await.claimable, 0);
            assert_supply(&db, &native, &[]).await;
        });
    }
}
