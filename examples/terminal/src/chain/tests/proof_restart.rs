use super::{fixture::ReadFixture, *};
use commonware_clearing::bajillion::{
    admission::bls12381,
    transition::{Header, RootBundle, WithdrawalClaim, prepare_close_with_strategy},
};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{Strategizer as _, reschedule};
use commonware_utils::{Faults as _, N3f1};
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
    range: commonware_clearing::bajillion::transition::ActivityRange<Digest>,
}

struct RestartExpected {
    identity: Genesis,
    scheme: Threshold,
    historical: CloseExpected,
    live: CloseExpected,
    predecessor: StateRoot<Digest>,
    predecessor_operations: u64,
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

#[commonware_macros::boxed]
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

#[commonware_macros::boxed]
async fn state_lookup(
    context: &deterministic::Context,
    root: StateRoot<Digest>,
    operations: u64,
    account: &Key,
) -> Option<NonZeroU64> {
    let EvidenceResponse::Served(Evidence::State(lookup)) = evidence(
        context,
        EvidenceLookup::State {
            root,
            operations,
            account: account.clone(),
        },
    )
    .await
    else {
        panic!("validator did not serve the Current proof")
    };
    lookup
        .resolve::<Sha256>(&root, &account_key(account).unwrap())
        .unwrap()
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
    let quorum = N3f1::quorum(scheme.committee().members().len()) as usize;
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
    scheme.assemble(votes).unwrap()
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
    let (expected, checkpoint) = runner.start_and_recover(prepare_history);
    deterministic::Runner::from(checkpoint).start(|context| verify_recovered(context, expected));
}

#[commonware_macros::boxed]
async fn prepare_history(context: deterministic::Context) -> RestartExpected {
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
    let network_context = context.child("initial_da_network");
    let ((mut da_sender, mut da_receiver), validator_channel) =
        da::tests::network(&network_context, &operator, &validator, true, true).await;
    let clearing =
        bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap()).unwrap();
    let strategy = context.strategy(NZUsize!(1));
    let (sealer, mailbox) = da::Sealer::new(
        context.child("initial_sealer"),
        da::Config {
            strategy: strategy.clone(),
            page_cache: crate::protocol::fixture_page_cache(&context),
            retain_history: true,
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

    let genesis_balances = crate::protocol::genesis_balances(&configured).unwrap();
    let mut liability = genesis_balances.iter().fold(0u64, |total, (_, balance)| {
        total.checked_add(balance.get()).unwrap()
    });
    let mut balances = Box::pin(
        crate::protocol::init_replica(
            context.child("operator_balances"),
            "proof-restart-operator",
            strategy.clone(),
            genesis_balances,
        )
        .await
        .unwrap()
        .sync(),
    )
    .await
    .unwrap();
    let wallets = wallets();
    let payer = wallets[0].public_key();
    let recipient = wallets[1].public_key();
    let withdrawal_account = wallets[2].public_key();
    let inactive = wallets[3].public_key();
    let missing = crate::protocol::eve_identity().key;
    let predecessor = balances.state().root();
    let predecessor_operations = balances.state().head().operations();
    let predecessor_balance = balances
        .state()
        .opening(payer.clone())
        .await
        .unwrap()
        .balance
        .get();

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
                    opening: balances
                        .state()
                        .opening(request.account().clone())
                        .await
                        .unwrap(),
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
            .bind::<Sha256, _, _>(&balances, &deposits, &withdrawals, registered.floors)
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
            &strategy,
        )
        .await
        .unwrap();
        let expected = CloseExpected {
            range: prepared
                .close()
                .roots
                .activity_range(&close_context)
                .unwrap(),
            header: prepared.close().header,
            roots: prepared.close().roots,
        };
        let withdrawal_position =
            (epoch == 0).then_some(close_context.predecessor_logs().payouts.operations);
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
        liability = liability
            .checked_add(deposit_amount)
            .and_then(|total| total.checked_sub(ballot.withdrawal_total))
            .unwrap();
        let queried = if epoch == 0 { &payer } else { &recipient };
        let balance = state_lookup(
            &context,
            expected.roots.successor,
            expected.roots.successor_operations,
            queried,
        )
        .await
        .unwrap();
        if epoch == 0 {
            successor_balance = Some(balance.get());
        }
        let (_, candidate) = prepared.into_parts();
        balances = Box::pin(balances.apply(candidate).await.unwrap().sync())
            .await
            .unwrap();
        assert_eq!(balances.state().root(), expected.roots.successor);
        if let Some(position) = withdrawal_position {
            let (opening, operations) = balances
                .logs()
                .payout_opening(
                    &expected.roots.withdrawal_outputs,
                    position,
                    NonZeroU64::MIN,
                )
                .await
                .unwrap();
            let [commonware_storage::qmdb::keyless::Operation::Append(output)] =
                operations.as_slice()
            else {
                panic!("withdrawal output is not the native payout append")
            };
            let output = WithdrawalClaim::new(output.clone(), opening)
                .verify::<Sha256>(&expected.roots.withdrawal_outputs)
                .unwrap();
            assert_eq!(output.destination().as_ref(), withdrawal_account.as_ref());
            assert_eq!(output.amount(), 7);
            withdrawal_amount = Some(output.amount());
        }
        if epoch == 0 {
            recipient_balance_before_live = Some(
                balances
                    .state()
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
    let live_recipient_balance = recipient_balance_before_live
        .unwrap()
        .checked_add(2)
        .unwrap();
    let withdrawal_amount = withdrawal_amount.unwrap();
    assert_eq!(
        balances
            .state()
            .opening(payer.clone())
            .await
            .unwrap()
            .balance
            .get(),
        successor_balance
    );
    assert_ne!(historical.roots.successor, live.roots.successor);
    while status(&fixture.db).await.last_finalized != Some(1) {
        accepted = Some(fixture.seal(&context, true).await);
    }
    assert_eq!(
        read(&fixture.db, &admitted_key(&deployment(), 0)).await,
        None
    );
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
        predecessor_operations,
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
}

#[commonware_macros::boxed]
async fn verify_recovered(context: deterministic::Context, expected: RestartExpected) {
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
    let network_context = context.child("restarted_da_network");
    let (_, validator_channel) =
        da::tests::network(&network_context, &operator, &validator, true, true).await;
    let clearing =
        bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap()).unwrap();
    let (sealer, mailbox) = da::Sealer::new(
        context.child("restarted_sealer"),
        da::Config {
            strategy: context.strategy(NZUsize!(1)),
            page_cache: crate::protocol::fixture_page_cache(&context),
            retain_history: true,
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

    assert_eq!(
        state_lookup(
            &context,
            expected.predecessor,
            expected.predecessor_operations,
            &expected.payer
        )
        .await
        .unwrap()
        .get(),
        expected.predecessor_balance
    );
    assert_eq!(
        metric_sum(
            &context,
            "restarted_sealer_replica_state",
            "apply_batch_calls_total"
        ),
        0,
        "a committed native account head must not replay on restart"
    );
    assert_eq!(
        state_lookup(
            &context,
            expected.historical.roots.successor,
            expected.historical.roots.successor_operations,
            &expected.payer
        )
        .await
        .unwrap()
        .get(),
        expected.successor_balance
    );
    assert_eq!(
        state_lookup(
            &context,
            expected.historical.roots.successor,
            expected.historical.roots.successor_operations,
            &expected.missing
        )
        .await,
        None
    );

    let Some(Record::PayoutHead(tip)) = read(&fixture.db, &payout_head_key(&deployment())).await
    else {
        panic!("finalized paired log heads")
    };
    assert_eq!(tip.finalized, Some(1));
    assert_eq!(tip.payouts, expected.live.roots.withdrawal_outputs);
    let range = expected.historical.range;
    for (account, debit, present) in [
        (expected.payer.clone(), 3, true),
        (expected.inactive.clone(), 0, false),
    ] {
        let EvidenceResponse::Served(Evidence::Account(lookup)) = evidence(
            &context,
            EvidenceLookup::Account {
                epoch: 0,
                range,
                account: account.clone(),
            },
        )
        .await
        else {
            panic!("historical account proof")
        };
        let (found_debit, changed) = lookup.resolve::<Sha256>(&range, &account).unwrap();
        assert_eq!(found_debit, debit);
        assert_eq!(changed.is_some(), present);
    }
    for (recipient, amount) in [
        (expected.recipient.clone(), (3, 1)),
        (expected.inactive.clone(), (0, 0)),
    ] {
        let EvidenceResponse::Served(Evidence::CommittedEntry(lookup)) = evidence(
            &context,
            EvidenceLookup::CommittedEntry {
                epoch: 0,
                range,
                payer: expected.payer.clone(),
                recipient: recipient.clone(),
            },
        )
        .await
        else {
            panic!("historical entry proof")
        };
        assert_eq!(
            lookup
                .resolve::<Sha256>(&range, &expected.payer, &recipient)
                .unwrap(),
            amount
        );
    }
    let index = expected.historical.roots.withdrawal_outputs.operations - 2;
    let EvidenceResponse::Served(Evidence::Payout(claim)) = evidence(
        &context,
        EvidenceLookup::Payout {
            head: tip.payouts,
            index,
        },
    )
    .await
    else {
        panic!("native payout proof")
    };
    let output = claim.verify::<Sha256>(&tip.payouts).unwrap();
    assert_eq!(output.amount(), expected.withdrawal_amount);
    assert_eq!(
        output.destination(),
        expected.withdrawal.body().destination()
    );
    assert_eq!(
        state_lookup(
            &context,
            expected.live.roots.successor,
            expected.live.roots.successor_operations,
            &expected.recipient
        )
        .await
        .unwrap()
        .get(),
        expected.live_recipient_balance
    );
    assert!(
        !commonware_runtime::Metrics::encode(&context).contains("restarted_sealer_archive"),
        "proof serving must use native stores"
    );
}
