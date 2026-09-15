use super::{fixture::ReadFixture, *};
use commonware_clearing::bajillion::{
    admission::bls12381,
    challenge::AccountLookup,
    qmdb::{State, StateLookup},
    transition::{Header, RootBundle, prepare_close_with_strategy},
};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::reschedule;
use std::net::SocketAddr;

const DA_PARTITION: &str = "proof-restart-da";
const CHAIN_PARTITION: &str = "native-reads";

fn query_address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 19_876))
}

#[derive(Clone, Debug)]
struct CloseExpected {
    header: Header<Digest>,
    roots: RootBundle<Digest>,
    batch: Digest,
}

struct RestartExpected {
    identity: Genesis,
    scheme: Threshold,
    historical: CloseExpected,
    live: CloseExpected,
    predecessor: StateRoot<Digest>,
    payer: Key,
    recipient: Key,
    inactive: Key,
    missing: Key,
    predecessor_balance: u64,
    successor_balance: u64,
    live_recipient_balance: u64,
    withdrawal: SignedWithdrawal<Key, Digest>,
    withdrawal_amount: u64,
}

async fn evidence(context: &deterministic::Context, lookup: EvidenceLookup) -> EvidenceResponse {
    let request = rpc::Request {
        method: query::METHOD_EVIDENCE,
        body: EvidenceRequest::new(deployment(), lookup).encode(),
    };
    let mut attempts = 0;
    let response = loop {
        match rpc::call(context, query_address(), &request).await {
            Ok(response) => break response,
            Err(error) => {
                attempts += 1;
                assert!(
                    attempts < SUBMIT_ATTEMPTS,
                    "evidence RPC did not become ready: {error:#}"
                );
                context.sleep(POLL).await;
            }
        }
    };
    let rpc::Response::Success { body } = response else {
        panic!("evidence RPC returned {response:?}");
    };
    EvidenceResponse::decode(body).expect("evidence response decodes")
}

async fn close_body(
    context: &deterministic::Context,
    expected: &CloseExpected,
    lookup: EvidenceLookup,
) -> EvidenceBody {
    let EvidenceResponse::Served(Evidence::Close {
        header,
        roots,
        body,
    }) = evidence(context, lookup).await
    else {
        panic!("validator did not serve close evidence");
    };
    assert_eq!(header, expected.header);
    assert_eq!(roots, expected.roots);
    body
}

fn metric_sum(context: &deterministic::Context, actor: &str, metric: &str) -> u64 {
    let encoded = commonware_runtime::Metrics::encode(context);
    let mut found = 0;
    let mut total = 0;
    for line in encoded.lines() {
        let Some((name, value)) = line.split_once(' ') else {
            continue;
        };
        let name = name.split_once('{').map_or(name, |(name, _)| name);
        if name.contains(actor) && name.ends_with(metric) {
            found += 1;
            total += value.parse::<u64>().expect("counter is an integer");
        }
    }
    assert!(found > 0, "missing {actor} {metric} counter");
    total
}

fn exact_certificate(scheme: &bls12381::Scheme, ballot: &da::Ballot) -> bls12381::Certificate {
    let quorum = scheme.committee().quorum();
    let mut votes = vec![ballot.vote.clone()];
    for index in 1..scheme.committee().members().len() {
        if votes.len() == quorum {
            break;
        }
        let signer =
            bls12381::Scheme::signer(committee().unwrap(), clearing_private(index).unwrap())
                .unwrap();
        assert_ne!(signer.me(), scheme.me());
        votes.push(signer.sign(&ballot.header).unwrap());
    }
    assert_eq!(votes.len(), quorum);
    scheme.assemble_exact(votes).unwrap()
}

async fn submit_one(
    fixture: &mut ReadFixture,
    context: &deterministic::Context,
    tx: SettlementTx,
) -> Block {
    fixture.submit(context, tx.clone()).await;
    let block = fixture.seal(context, true).await;
    assert_eq!(block.transactions, vec![tx]);
    block
}

/// A canonical close's individually persisted proof material remains available after every
/// actor, database handle, and derived close object has been discarded and reopened.
#[test]
fn accepted_close_proofs_survive_full_validator_restart() {
    let runner = deterministic::Runner::timed(Duration::from_secs(90));
    let (expected, checkpoint) = runner.start_and_recover(|context| async move {
        let mut fixture = ReadFixture::new(&context).await;
        fixture.seal(&context, true).await;
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let deployment_entry = fixture
            .identity
            .native
            .deployments
            .iter()
            .find(|entry| entry.deployment.digest() == &deployment())
            .unwrap()
            .clone();
        let configured = deployment_entry.deployment.clone();
        let chain_id = fixture.identity.native.chain_id();
        let operator = deployment_entry.network_key;
        let validator = ed25519::PrivateKey::from_seed(91_026).public_key();
        let ((mut da_sender, mut da_receiver), validator_channel) = da::tests::network(
            &context.child("initial_da_network"),
            &operator,
            &validator,
            true,
            true,
        )
        .await;
        let clearing =
            bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap()).unwrap();
        let (sealer, mailbox) = da::Sealer::new(
            context.child("initial_sealer"),
            da::Config {
                scheme: clearing.clone(),
                registry: fixture.registry.clone(),
                db: fixture.db.clone(),
                partition: DA_PARTITION.into(),
                validators: Vec::new(),
                fetch_timeout: Duration::from_millis(100),
            },
        );
        let _sealer = sealer.start(validator_channel);
        let _query = query::start(
            context.child("initial_proof_query"),
            query::Config {
                address: query_address(),
                db: fixture.db.clone(),
                finalized: fixture.finalized.clone(),
                marshal: fixture.marshal.clone(),
                ingress: fixture.ingress.clone(),
                sealer: Some(mailbox),
            },
        );

        let mut balances = State::<_, Sha256>::init(
            context.child("operator_balances"),
            crate::protocol::state_config("proof-restart-operator", &context, Sequential),
            crate::protocol::genesis_balances(&configured).unwrap(),
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
        let wallets = wallets();
        let payer = wallets[0].public_key();
        let recipient = wallets[1].public_key();
        let withdrawal_account = wallets[2].public_key();
        let inactive = wallets[3].public_key();
        let missing = crate::protocol::eve_identity().key;
        let predecessor = balances.root();
        let predecessor_balance = balances.opening(payer.clone()).await.unwrap().balance.get();

        let withdrawal = SignedWithdrawal::sign(
            deployment(),
            predecessor.digest,
            withdrawal_account.encode(),
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            100,
            wallets[2].signer(),
        );
        let inputs = [
            (payer.clone(), 1, Some(withdrawal.clone()), true),
            (recipient.clone(), 2, None, false),
        ];
        let mut closes = Vec::with_capacity(inputs.len());
        let mut successor_balance = None;
        let mut recipient_balance_before_live = None;
        let mut withdrawal_amount = None;
        let mut accepted = None;
        for (epoch, (deposit_account, deposit_amount, withdrawal_request, sends)) in
            inputs.into_iter().enumerate()
        {
            let epoch = u64::try_from(epoch).unwrap();
            let deposit_event = DepositEvent {
                id: Sha256::hash(&[b"proof-restart-deposit", &epoch.to_be_bytes()]),
                account: deposit_account,
                amount: deposit_amount,
            };
            submit_one(
                &mut fixture,
                &context,
                SettlementTx::Deposit(signed_deposit(
                    chain_id,
                    deployment(),
                    deposit_event.clone(),
                )),
            )
            .await;
            let withdrawals = if let Some(request) = withdrawal_request {
                submit_one(
                    &mut fixture,
                    &context,
                    SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                        opening: balances.opening(request.account().clone()).await.unwrap(),
                        request: request.clone(),
                    }),
                )
                .await;
                WithdrawalBatch::new(vec![request]).unwrap()
            } else {
                WithdrawalBatch::empty()
            };
            let deposits = DepositBatch::new(vec![
                DepositRecord::new(deposit_event.account, deposit_event.amount).unwrap(),
            ])
            .unwrap();
            let deposits_root = deposits.root::<Sha256>().unwrap();
            let liability = balances.liability();
            submit_one(
                &mut fixture,
                &context,
                SettlementTx::RegisterEpoch(RegisterEpochRequest {
                    fee: 4096,
                    deployment: deployment(),
                    epoch,
                    predecessor_liability: liability,
                    deposits_root,
                    withdrawals: withdrawals.clone(),
                    openings: Vec::new(),
                    signature: protocol.sign_chain_registration(
                        epoch,
                        liability,
                        &deposits_root,
                        &withdrawals,
                        4096,
                    ),
                }),
            )
            .await;
            let registered = registration(&fixture.db).await;
            assert_eq!(registered.epoch, epoch);
            let registration = protocol
                .registration_at(
                    epoch,
                    deposits.clone(),
                    withdrawals.clone(),
                    liability,
                    registered.admission_deadline,
                    registered.challenge_deadline,
                )
                .unwrap();
            let close_context = registration
                .context
                .bind::<Sha256, _, _>(&balances, &deposits, &withdrawals)
                .unwrap();
            let terminals = if sends {
                let vector = OutVector::new(
                    epoch,
                    payer.clone(),
                    vec![OutEntry {
                        recipient: recipient.clone(),
                        cumulative: 3,
                        count: 1,
                    }],
                )
                .unwrap();
                let body = VectorSendBody::new(
                    close_context.payment(),
                    payer.clone(),
                    1,
                    3,
                    vector.root::<Sha256, Digest>().unwrap(),
                );
                vec![Terminal {
                    operator_signature: protocol.sign_ack_aggregate(&body),
                    authorization: SendAuthorization::sign(body, wallets[0].signer()),
                    vector,
                }]
            } else {
                Vec::new()
            };
            let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &balances,
                &close_context,
                &deposits,
                &withdrawals,
                terminals,
                &Sequential,
            )
            .await
            .unwrap();
            let expected = CloseExpected {
                header: prepared.close().header,
                roots: prepared.close().roots,
                batch: prepared.close().header.batch_id::<Sha256>().into_digest(),
            };
            if epoch == 0 {
                let amount = prepared
                    .withdrawal_claim(&withdrawal_account)
                    .unwrap()
                    .output()
                    .amount();
                assert_eq!(amount, 7);
                withdrawal_amount = Some(amount);
            }
            assert!(
                !da_sender
                    .send(
                        Recipients::One(validator.clone()),
                        da::Message::Dealing(Box::new(da::Dealing {
                            deployment: deployment(),
                            epoch,
                            context: close_context.epoch_context().clone(),
                            bytes: prepared.encoded().clone(),
                        }))
                        .encode(),
                        true,
                    )
                    .is_empty()
            );
            let (sender, wire) = commonware_macros::select! {
                result = da_receiver.recv() => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("validator did not accept epoch {epoch}"),
            };
            assert_eq!(sender, validator);
            let da::Message::Vote(ballot) = da::Message::decode(wire).unwrap() else {
                panic!("validator returned a non-vote message");
            };
            assert_eq!(ballot.epoch, epoch);
            assert_eq!(ballot.header, expected.header);
            assert_eq!(ballot.roots, expected.roots);
            assert!(clearing.verify_vote(&ballot.header, &ballot.vote));
            accepted = Some(
                submit_one(
                    &mut fixture,
                    &context,
                    SettlementTx::Admit(AdmitRequest {
                        deployment: deployment(),
                        epoch,
                        header: ballot.header,
                        roots: ballot.roots,
                        withdrawal_total: ballot.withdrawal_total,
                        certificate: exact_certificate(&clearing, &ballot),
                    }),
                )
                .await,
            );
            let EvidenceBody::State(opening) = close_body(
                &context,
                &expected,
                EvidenceLookup::SuccessorState {
                    batch: expected.batch,
                    account: if epoch == 0 {
                        payer.clone()
                    } else {
                        recipient.clone()
                    },
                },
            )
            .await
            else {
                panic!("epoch-{epoch} reconciliation did not return its successor state");
            };
            let balance = opening.verify::<Sha256>(&expected.roots.successor).unwrap();
            if epoch == 0 {
                successor_balance = Some(balance.get());
            }
            let (_, candidate) = prepared.into_parts();
            balances = balances
                .apply(candidate)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            assert_eq!(balances.root(), expected.roots.successor);
            if epoch == 0 {
                recipient_balance_before_live = Some(
                    balances
                        .opening(recipient.clone())
                        .await
                        .unwrap()
                        .balance
                        .get(),
                );
            }
            closes.push(expected);
        }
        let [historical, live]: [CloseExpected; 2] = closes.try_into().unwrap();
        let successor_balance = successor_balance.unwrap();
        let live_recipient_balance = recipient_balance_before_live.unwrap().checked_add(2).unwrap();
        let withdrawal_amount = withdrawal_amount.unwrap();
        assert_eq!(
            balances.opening(payer.clone()).await.unwrap().balance.get(),
            successor_balance
        );
        assert_ne!(historical.roots.successor, live.roots.successor);
        let accepted = accepted.unwrap();
        while fixture.marshal.get_processed_height().await != Some(accepted.height) {
            reschedule().await;
        }

        RestartExpected {
            identity: fixture.identity.clone(),
            scheme: fixture.scheme.clone(),
            historical,
            live,
            predecessor,
            payer,
            recipient,
            inactive,
            missing,
            predecessor_balance,
            successor_balance,
            live_recipient_balance,
            withdrawal,
            withdrawal_amount,
        }
    });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        assert_ne!(
            expected.historical.roots.successor,
            expected.live.roots.successor
        );
        let fixture = ReadFixture::configured(
            &context,
            CHAIN_PARTITION,
            expected.identity.validators[0].query,
            expected.identity.clone(),
            expected.scheme.clone(),
            None,
        )
        .await;
        let operator = expected
            .identity
            .native
            .deployments
            .iter()
            .find(|entry| entry.deployment.digest() == &deployment())
            .unwrap()
            .network_key
            .clone();
        let validator = ed25519::PrivateKey::from_seed(91_026).public_key();
        let (_, validator_channel) = da::tests::network(
            &context.child("restarted_da_network"),
            &operator,
            &validator,
            true,
            true,
        )
        .await;
        let clearing =
            bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap()).unwrap();
        let (sealer, mailbox) = da::Sealer::new(
            context.child("restarted_sealer"),
            da::Config {
                scheme: clearing,
                registry: fixture.registry.clone(),
                db: fixture.db.clone(),
                partition: DA_PARTITION.into(),
                validators: Vec::new(),
                fetch_timeout: Duration::from_millis(100),
            },
        );
        let _sealer = sealer.start(validator_channel);
        let _query = query::start(
            context.child("restarted_proof_query"),
            query::Config {
                address: query_address(),
                db: fixture.db.clone(),
                finalized: fixture.finalized.clone(),
                marshal: fixture.marshal.clone(),
                ingress: fixture.ingress.clone(),
                sealer: Some(mailbox),
            },
        );

        let EvidenceResponse::Served(Evidence::Genesis(_)) = evidence(
            &context,
            EvidenceLookup::GenesisState {
                account: expected.payer.clone(),
            },
        )
        .await
        else {
            panic!("restarted validator did not finish recovery");
        };
        assert_eq!(
            metric_sum(
                &context,
                "restarted_sealer_balances",
                "apply_batch_calls_total"
            ),
            0,
            "a committed native account head must not replay on restart"
        );
        let canonical_gets = metric_sum(&context, "restarted_sealer_archive", "gets_total");
        assert!(canonical_gets >= 2, "recovery reads first and tail anchors");

        let EvidenceBody::State(opening) = close_body(
            &context,
            &expected.historical,
            EvidenceLookup::PredecessorState {
                batch: expected.historical.batch,
                account: expected.payer.clone(),
            },
        )
        .await
        else {
            panic!("historical predecessor opening was not served");
        };
        assert_eq!(
            opening
                .verify::<Sha256>(&expected.predecessor)
                .unwrap()
                .get(),
            expected.predecessor_balance
        );

        let EvidenceBody::State(opening) = close_body(
            &context,
            &expected.historical,
            EvidenceLookup::SuccessorState {
                batch: expected.historical.batch,
                account: expected.payer.clone(),
            },
        )
        .await
        else {
            panic!("historical successor opening was not served");
        };
        assert_eq!(
            opening
                .verify::<Sha256>(&expected.historical.roots.successor)
                .unwrap()
                .get(),
            expected.successor_balance
        );

        let EvidenceBody::StateAbsent(proof) = close_body(
            &context,
            &expected.historical,
            EvidenceLookup::SuccessorState {
                batch: expected.historical.batch,
                account: expected.missing.clone(),
            },
        )
        .await
        else {
            panic!("historical successor absence was not served");
        };
        assert_eq!(
            StateLookup::Absent(proof)
                .resolve::<Sha256>(
                    &expected.historical.roots.successor,
                    &account_key(&expected.missing).unwrap(),
                )
                .unwrap(),
            None
        );

        let EvidenceBody::Change(change) = close_body(
            &context,
            &expected.historical,
            EvidenceLookup::Change {
                batch: expected.historical.batch,
                account: expected.payer.clone(),
            },
        )
        .await
        else {
            panic!("historical change opening was not served");
        };
        let (debit, changed) = AccountLookup::Present(Box::new(change))
            .resolve::<Sha256>(&expected.historical.roots.change, &expected.payer)
            .unwrap();
        assert_eq!(debit, 3);
        assert!(changed.is_some());
        assert_eq!(
            evidence(
                &context,
                EvidenceLookup::Change {
                    batch: expected.historical.batch,
                    account: expected.inactive.clone(),
                },
            )
            .await,
            EvidenceResponse::Absent
        );

        for (account_key, expected_debit, expected_present) in [
            (expected.payer.clone(), 3, true),
            (expected.inactive.clone(), 0, false),
        ] {
            let EvidenceBody::Account(account) = close_body(
                &context,
                &expected.historical,
                EvidenceLookup::Account {
                    batch: expected.historical.batch,
                    account: account_key.clone(),
                },
            )
            .await
            else {
                panic!("historical account lookup was not served");
            };
            let (debit, changed) = account
                .resolve::<Sha256>(&expected.historical.roots.change, &account_key)
                .unwrap();
            assert_eq!(debit, expected_debit);
            assert_eq!(changed.is_some(), expected_present);
        }

        for (entry_recipient, expected_entry) in [
            (expected.recipient.clone(), (3, 1)),
            (expected.inactive.clone(), (0, 0)),
        ] {
            let EvidenceBody::CommittedEntry(entry) = close_body(
                &context,
                &expected.historical,
                EvidenceLookup::CommittedEntry {
                    batch: expected.historical.batch,
                    payer: expected.payer.clone(),
                    recipient: entry_recipient.clone(),
                },
            )
            .await
            else {
                panic!("historical entry lookup was not served");
            };
            assert_eq!(
                entry
                    .resolve::<Sha256>(
                        &expected.historical.roots.change,
                        &expected.payer,
                        &entry_recipient,
                    )
                    .unwrap(),
                expected_entry
            );
        }

        let EvidenceBody::WithdrawalOutput(witness) = close_body(
            &context,
            &expected.historical,
            EvidenceLookup::WithdrawalOutput {
                batch: expected.historical.batch,
                account: expected.withdrawal.account().clone(),
            },
        )
        .await
        else {
            panic!("historical withdrawal output was not served");
        };
        assert_eq!(witness.request, expected.withdrawal);
        assert_eq!(witness.claim.output().amount(), expected.withdrawal_amount);
        assert_eq!(
            witness
                .verify(
                    &expected.historical.roots,
                    &deployment(),
                    expected.withdrawal.account(),
                    expected.withdrawal.body().destination().as_ref(),
                )
                .unwrap()
                .into_digest(),
            expected.historical.batch
        );

        let EvidenceBody::State(opening) = close_body(
            &context,
            &expected.live,
            EvidenceLookup::SuccessorState {
                batch: expected.live.batch,
                account: expected.recipient.clone(),
            },
        )
        .await
        else {
            panic!("recovered live successor opening was not served");
        };
        let live_recipient = opening
            .verify::<Sha256>(&expected.live.roots.successor)
            .unwrap();
        assert_eq!(live_recipient.get(), expected.live_recipient_balance);
        assert_eq!(
            metric_sum(&context, "restarted_sealer_archive", "gets_total"),
            canonical_gets,
            "ordinary proof RPCs must not decode whole canonical close records"
        );

        let EvidenceResponse::Served(Evidence::Dealing(replay)) =
            evidence(&context, EvidenceLookup::Dealing { epoch: 0 }).await
        else {
            panic!("unpruned canonical replay was not served");
        };
        assert_eq!(replay.header, expected.historical.header);
        assert_eq!(replay.roots, expected.historical.roots);
        let EvidenceBody::Complete { context: close, .. } = close_body(
            &context,
            &expected.historical,
            EvidenceLookup::CloseEvidence {
                batch_id: expected.historical.header.batch_id::<Sha256>(),
            },
        )
        .await
        else {
            panic!("unpruned complete close evidence was not served");
        };
        assert_eq!(close.deployment(), &deployment());
    });
}
