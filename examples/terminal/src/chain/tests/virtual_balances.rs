use super::*;

#[test]
fn funded_owner_outside_genesis_can_deposit() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("dynamic_deposit"), "dynamic-deposit").await;
        let native = native();
        let owner = crate::protocol::Wallet::from_seed("new-owner", 991_001);
        let funder = wallets().remove(0);
        let funding = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"dynamic-funding"]),
            owner.public_key(),
            7,
            funder.signer(),
        ));
        let event = DepositEvent {
            id: Sha256::hash(&[b"dynamic-deposit"]),
            account: owner.public_key(),
            amount: 7,
        };
        let deposit = SettlementTx::Deposit(DepositRequest::sign(
            native.chain_id(),
            deployment(),
            event.clone(),
            owner.signer(),
        ));
        seal_native(&db, 1, &native, &[funding]).await;
        assert_eq!(
            native_balance(&db, &native, &owner.public_key())
                .await
                .unwrap(),
            7
        );
        seal_native(&db, 2, &native, &[deposit.clone(), deposit]).await;
        assert_eq!(
            read(&db, &deposit_key(&deployment(), &event.id)).await,
            Some(Record::Deposit(event))
        );
        assert_eq!(
            native_balance(&db, &native, &owner.public_key())
                .await
                .unwrap(),
            0
        );
        assert_eq!(status(&db).await.custody, 407);
        assert_supply(&db, &native, &[owner.public_key()]).await;
    });
}

#[test]
fn runtime_registration_starts_empty() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("empty_registration"), "empty-registration").await;
        let native = native();
        let owner = operator_signer(10);
        let funding = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
            native.chain_id(), Sha256::hash(&[b"empty-registration-funding"]), owner.public_key(), 10,
            wallets()[0].signer(),
        ));
        let request = RegisterDeploymentRequest::sign(native.chain_id(), Sha256::hash(&[b"empty-registration"]),
            operator_ack_key(10), ed25519::PrivateKey::from_seed(991_002).public_key(), 1024, 10, &owner);
        let id = request.deployment_id();
        seal_native(&db, 1, &native, &[funding, SettlementTx::RegisterDeployment(request)]).await;
        let entry = registry_entry(&db, &native, &id).await.unwrap().expect("empty registration is valid");
        assert!(entry.deployment.accounts.is_empty());
        assert!(matches!(read(&db, &status_key(&id)).await, Some(Record::Status(status)) if status.custody == 0));
    });
}

#[test]
fn first_virtual_credit_waits_for_explicit_withdrawal() {
    first_credit(false);
}

#[test]
fn invalidated_first_credit_has_no_frozen_entitlement() {
    first_credit(true);
}

fn first_credit(invalidated: bool) {
    deterministic::Runner::default().start(|context| async move {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let genesis = genesis_cache();
        let payer = wallets().remove(0);
        let recipient = crate::protocol::Wallet::from_seed("new-recipient", 991_003);
        let native = native();
        let db = open(context.child("virtual_credit"), "virtual-credit").await;
        let config = crate::protocol::state_config(
            "virtual-balances",
            &context,
            protocol.strategy().clone(),
        );
        let mut balances = replay_state(context.child("balances"), config, &genesis.history).await;
        let deposits_root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
        let native_key =
            super::super::state::native_balance_key(&native.chain_id(), &recipient.public_key());
        let queue_key = withdrawal_key(&deployment(), &recipient.public_key());
        let notice = crate::protocol::settlement_config(&Timing::DEFAULT)
            .unwrap()
            .minimum_withdrawal_notice
            .get();
        let queues = |root: StateRoot<Digest>, opening: StateOpening<Key, Digest>, height: u64| {
            [
                WithdrawalAction::Amount(NonZeroU64::MIN),
                WithdrawalAction::Close,
            ]
            .into_iter()
            .map(|action| {
                SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                    request: SignedWithdrawal::sign(
                        deployment(),
                        root.digest,
                        recipient.public_key().encode(),
                        action,
                        height + notice,
                        recipient.signer(),
                    ),
                    openings: vec![opening.clone()],
                })
            })
            .collect::<Vec<_>>()
        };
        let register = |epoch, liability, withdrawals: WithdrawalBatch<Key, Digest>, openings| {
            SettlementTx::RegisterEpoch(RegisterEpochRequest {
                deployment: deployment(),
                epoch,
                predecessor_liability: liability,
                deposits_root,
                signature: protocol.sign_chain_registration(
                    epoch,
                    liability,
                    &deposits_root,
                    &withdrawals,
                    4096,
                ),
                withdrawals,
                openings,
                fee: 4096,
            })
        };
        seal_native(
            &db,
            1,
            &native,
            &queues(
                genesis.root(),
                genesis.opening(&payer.public_key()).unwrap(),
                1,
            ),
        )
        .await;
        assert_eq!(read(&db, &queue_key).await, None);
        let mut height = 2;
        let mut total = 0;
        for (epoch, amount) in [7, 5].into_iter().enumerate() {
            let epoch = epoch as u64;
            total += amount;
            let withdrawals = WithdrawalBatch::empty();
            let registration = protocol
                .registration_at(
                    epoch,
                    DepositBatch::empty(),
                    withdrawals.clone(),
                    400,
                    height + 10,
                    height + 11,
                )
                .unwrap();
            let vector = OutVector::new(
                epoch,
                payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.public_key(),
                    cumulative: amount,
                    count: 1,
                }],
            )
            .unwrap();
            let body = VectorSendBody::new(
                registration.context.payment(),
                payer.public_key(),
                1,
                amount,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            let terminal = Terminal {
                operator_signature: protocol.sign_ack_aggregate(&body),
                authorization: SendAuthorization::sign(body, payer.signer()),
                vector,
            };
            let prepared = protocol
                .prepare(registration, &balances, vec![terminal])
                .await
                .unwrap();
            assert!(
                prepared.mutations().contains(&(
                    account_key(&recipient.public_key()).unwrap(),
                    NonZeroU64::new(total)
                )),
                "credits accumulate in the virtual leaf"
            );
            let mutations = prepared.mutations().to_vec();
            let result = protocol
                .complete(prepared, &balances, &mut TestRng::new(91 + epoch))
                .await
                .unwrap()
                .0;
            assert!(result.withdrawal_claims.is_empty());
            let candidate = balances.prepare(balances.head(), mutations).await.unwrap();
            balances = balances.apply(candidate).await.unwrap();
            let mut transactions = if epoch == 0 {
                queues(
                    genesis.root(),
                    balances.opening(recipient.public_key()).await.unwrap(),
                    height,
                )
            } else {
                Vec::new()
            };
            transactions.extend([
                register(epoch, 400, withdrawals, Vec::new()),
                SettlementTx::Admit(AdmitRequest::from(&result)),
            ]);
            seal_native(&db, height, &native, &transactions).await;
            assert_eq!(read(&db, &queue_key).await, None);
            if invalidated {
                seal_native(
                    &db,
                    height + 1,
                    &native,
                    &[
                        SettlementTx::Challenge(ChallengeRequest {
                            deployment: deployment(),
                            batch_id: result.header.batch_id::<Sha256>(),
                            evidence: ack_fork(&result, &protocol, (2, 3)).encode(),
                        }),
                        SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest {
                            deployment: deployment(),
                        }),
                        SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
                            deployment: deployment(),
                            opening: balances.opening(recipient.public_key()).await.unwrap(),
                        }),
                    ],
                )
                .await;
                assert!(status(&db).await.hard_faulted);
                assert_eq!(status(&db).await.state_root, genesis.root());
                assert_eq!(status(&db).await.custody, 400);
                assert_eq!(status(&db).await.claimable, 0);
                assert_eq!(
                    read(
                        &db,
                        &claim_roots_key(&deployment(), &result.header.batch_id::<Sha256>())
                    )
                    .await,
                    None
                );
                assert_eq!(
                    read(&db, &hard_fault_key(&deployment(), &recipient.public_key())).await,
                    None
                );
                assert_eq!(read(&db, &native_key).await, None);
                let claims = genesis
                    .accounts
                    .iter()
                    .map(|account| {
                        SettlementTx::ClaimHardFault(ClaimHardFaultRequest {
                            deployment: deployment(),
                            opening: genesis.opening(&account.key).unwrap(),
                        })
                    })
                    .collect::<Vec<_>>();
                seal_native(&db, height + 2, &native, &claims).await;
                assert_eq!(status(&db).await.custody, 0);
                assert_supply(&db, &native, &[recipient.public_key()]).await;
                return;
            }
            seal_native(&db, height + 12, &native, &[]).await;
            assert!(!status(&db).await.hard_faulted);
            assert_eq!(status(&db).await.last_finalized, Some(epoch));
            assert_eq!(status(&db).await.custody, 400);
            assert_eq!(status(&db).await.claimable, 0);
            assert_eq!(read(&db, &native_key).await, None);
            assert_supply(&db, &native, &[recipient.public_key()]).await;
            height += 13;
        }
        let opening = balances.opening(recipient.public_key()).await.unwrap();
        let request = SignedWithdrawal::sign(
            deployment(),
            balances.head().root().digest,
            recipient.public_key().encode(),
            WithdrawalAction::Close,
            height + notice,
            recipient.signer(),
        );
        let withdrawals = WithdrawalBatch::new(vec![request]).unwrap();
        let registration = protocol
            .registration_at(
                2,
                DepositBatch::empty(),
                withdrawals.clone(),
                400,
                height + 10,
                height + 11,
            )
            .unwrap();
        let prepared = protocol
            .prepare(registration, &balances, Vec::new())
            .await
            .unwrap();
        assert!(
            prepared
                .mutations()
                .contains(&(account_key(&recipient.public_key()).unwrap(), None))
        );
        let result = protocol
            .complete(prepared, &balances, &mut TestRng::new(93))
            .await
            .unwrap()
            .0;
        assert_eq!(result.withdrawal_claims.len(), 1);
        let claim = SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
            deployment: deployment(),
            batch_id: result.header.batch_id::<Sha256>(),
            claim: result.withdrawal_claims[0].clone(),
        });
        seal_native(
            &db,
            height,
            &native,
            &[
                register(2, 400, withdrawals, vec![opening.clone()]),
                SettlementTx::Admit(AdmitRequest::from(&result)),
                claim.clone(),
            ],
        )
        .await;
        assert_eq!(read(&db, &native_key).await, None);
        seal_native(&db, height + 12, &native, &[]).await;
        assert_eq!(status(&db).await.claimable, total);
        let claims_key = claim_roots_key(&deployment(), &result.header.batch_id::<Sha256>());
        let finalized_claims = read(&db, &claims_key).await;
        height += 13;
        let mut transactions = queues(result.roots.successor, opening, height);
        transactions.push(register(
            3,
            400 - total,
            WithdrawalBatch::empty(),
            Vec::new(),
        ));
        seal_native(&db, height, &native, &transactions).await;
        assert_eq!(read(&db, &queue_key).await, None);
        seal_native(&db, height + 11, &native, &[]).await;
        assert!(status(&db).await.hard_faulted);
        assert_eq!(read(&db, &claims_key).await, finalized_claims);
        assert_eq!(status(&db).await.claimable, total);
        seal_native(&db, height + 12, &native, &[claim.clone(), claim.clone()]).await;
        assert_eq!(
            native_balance(&db, &native, &recipient.public_key())
                .await
                .unwrap(),
            total
        );
        assert_eq!(status(&db).await.custody, 400 - total);
        assert_eq!(status(&db).await.claimable, 0);
        assert_supply(&db, &native, &[recipient.public_key()]).await;
        let consumed = read(&db, &claims_key).await;
        assert_ne!(consumed, finalized_claims);
        assert!(db.finalize().await.durable().await);
        drop(db);
        let db = open(context.child("reopened"), "virtual-credit").await;
        seal_native(&db, height + 13, &native, &[claim]).await;
        assert_eq!(read(&db, &claims_key).await, consumed);
        assert_eq!(
            native_balance(&db, &native, &recipient.public_key())
                .await
                .unwrap(),
            total
        );
        assert_supply(&db, &native, &[recipient.public_key()]).await;
    });
}
