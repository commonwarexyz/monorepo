use super::{
    custody::{DEPOSIT_ID_NAMESPACE, withdrawal_deadline},
    evidence::Holders,
    store::{IncomingSummary, PendingWithdrawalClaim},
    *,
};
use crate::{
    chain::{
        client::{Chain as _, Client},
        harness,
        query::{Evidence, EvidenceResponse},
        state::{
            Advice, FaultRecord, HardFaultReasonResponse, Record, RegistrationRecord, Reject,
            admitted_key, deposit_key, fault_key, registration_key, status_key, withdrawal_key,
        },
        tx::{AdmitRequest, RegisterEpochRequest, SettlementTx},
    },
    operator::{Operator, rpc as operator_rpc},
    protocol::{
        Acceptance, AcceptedEntry, AccountCache, Ack, DepositEvent, Entry, INITIAL_BALANCE, Key,
        Protocol, Receipt, SettlementResult, Wallet, deployment, external_identity, identities,
        operator_key, wallets,
    },
    rpc,
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalAction, WithdrawalBatch},
    payment::{PaymentContext, SendAuthorization, VECTOR_ACK_SIGNATURE_NAMESPACE, VectorSendBody},
    state::{AccountState, StateLeaf},
    transition::BatchId,
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::{
    Clock as _, Listener as _, Network, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::TestRng;
use std::{
    fs,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

/// The in-process chain's query address.
const CHAIN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_600);

/// An address nothing ever binds: the unreachable operator, and the dead
/// holder every evidence request fails against.
const UNREACHABLE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_602);

static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "commonware-terminal-agent-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("agent.sqlite");
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

/// Starts the settlement chain and a verified client over it.
async fn chain(context: &deterministic::Context) -> (harness::Control, Client) {
    let control = harness::start(context, CHAIN, "chain").await;
    let client = Client::new(
        control.identity(),
        deployment(),
        vec![CHAIN],
        context.child("client_rng"),
    )
    .unwrap();
    (control, client)
}

/// A verified client over the running chain whose genesis lists every
/// committee validator at `holders`, so evidence routes there while certified
/// reads stay on the chain. `UNREACHABLE` makes every holder decline, which
/// pins the operator fallback of a flow.
fn client_with_holders(
    context: &deterministic::Context,
    control: &harness::Control,
    holders: SocketAddr,
) -> Client {
    let mut genesis = control.identity().clone();
    for validator in &mut genesis.validators {
        validator.query = holders;
    }
    Client::new(
        &genesis,
        deployment(),
        vec![CHAIN],
        context.child("client_rng"),
    )
    .unwrap()
}

/// A verified client over the running chain whose genesis lists each committee
/// validator at its own address, `base` plus its committee index, so a test
/// can put a distinct server behind every holder of a slice.
fn client_with_distinct_holders(
    context: &deterministic::Context,
    control: &harness::Control,
    base: u16,
) -> Client {
    let mut genesis = control.identity().clone();
    for (index, validator) in genesis.validators.iter_mut().enumerate() {
        let index = u16::try_from(index).unwrap();
        validator.query = SocketAddr::from(([127, 0, 0, 1], base + index));
    }
    Client::new(
        &genesis,
        deployment(),
        vec![CHAIN],
        context.child("client_rng"),
    )
    .unwrap()
}

/// Serves evidence at `address` by forwarding every request to the chain,
/// counting the requests served.
async fn forwarding_holder(
    context: &deterministic::Context,
    address: SocketAddr,
) -> Arc<AtomicUsize> {
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let mut listener = context.bind(address).await.unwrap();
    context
        .child("forwarding_holder")
        .spawn(move |context| async move {
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                let response = rpc::call(&context, CHAIN, &request).await.unwrap();
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    served
}

/// Answers every request at `address` with `response`, counting the requests
/// answered: a holder that serves garbage.
async fn garbage_holder(
    context: &deterministic::Context,
    address: SocketAddr,
    response: rpc::Response,
) -> Arc<AtomicUsize> {
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let mut listener = context.bind(address).await.unwrap();
    context
        .child("garbage_holder")
        .spawn(move |context| async move {
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(_) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    served
}

/// Submits one transaction directly and asserts its effect record landed:
/// the domain-state completion every client flow performs.
async fn applied(control: &harness::Control, tx: &SettlementTx) {
    control.submit(tx.clone()).await;
    match tx {
        SettlementTx::Deposit(request) => assert!(matches!(
            control.record(deposit_key(&deployment(), &request.event.id)).await,
            Some(Record::Deposit(recorded)) if recorded == request.event
        )),
        SettlementTx::RegisterEpoch(request) => assert!(matches!(
            control.record(registration_key(&deployment())).await,
            Some(Record::Registration(record)) if record.epoch == request.epoch
        )),
        SettlementTx::Admit(request) => assert!(matches!(
            control
                .record(admitted_key(&deployment(), request.epoch))
                .await,
            Some(Record::Admitted(_))
        )),
        tx => panic!("no effect matcher for {tx:?}"),
    }
}

/// The certified registration record on the harness chain.
async fn registration_record(control: &harness::Control) -> RegistrationRecord {
    match control.record(registration_key(&deployment())).await {
        Some(Record::Registration(record)) => record,
        record => panic!("expected the registration record, found {record:?}"),
    }
}

/// Registers the operator's live epoch (boundary only), adopts the
/// chain-assigned deadlines from the certified registration record, and
/// returns the payment context every scripted head then serves.
async fn register(
    control: &harness::Control,
    operator: &mut Operator,
) -> PaymentContext<Key, Digest> {
    let request = operator.signed_registration().unwrap();
    applied(control, &SettlementTx::RegisterEpoch(request)).await;
    let record = registration_record(control).await;
    operator.adopt_registration(&record).unwrap();
    operator
        .payment_head(&wallets()[0].public_key())
        .unwrap()
        .context
}

/// Admits `result`'s close and drives the chain past its challenge window to
/// certified finalization.
async fn finalize(control: &harness::Control, result: &SettlementResult) {
    applied(control, &SettlementTx::Admit(AdmitRequest::from(result))).await;
    let deadline = result.epoch_context.challenge_deadline();
    let height = control.advance(0).await;
    if height <= deadline {
        control.advance(deadline - height + 1).await;
    }
    let status = status(control).await;
    assert!(
        status
            .last_finalized
            .is_some_and(|last| last >= result.epoch)
    );
}

/// The chain's status singleton, read directly for assertions.
async fn status(control: &harness::Control) -> crate::chain::state::StatusRecord {
    match control.record(status_key(&deployment())).await {
        Some(Record::Status(status)) => status,
        record => panic!("expected the status record, found {record:?}"),
    }
}

/// Registers an empty epoch-0 boundary and returns the chain-assigned
/// certified payment context, for scripted operators with no backing state
/// machine.
async fn registered_context(control: &harness::Control) -> PaymentContext<Key, Digest> {
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let deposits_root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let signature =
        protocol.sign_chain_registration(0, 400, &deposits_root, &deposits_root, &withdrawals);
    applied(
        control,
        &SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,
            staged_root: deposits_root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature,
        }),
    )
    .await;
    let record = registration_record(control).await;
    crate::protocol::epoch_context_at(
        deployment(),
        operator_key(),
        0,
        &DepositBatch::empty(),
        &withdrawals,
        400,
        record.admission_deadline,
        record.challenge_deadline,
    )
    .unwrap()
    .payment()
    .clone()
}

async fn respond_rpc<L: commonware_runtime::Listener>(
    listener: &mut L,
    handle: impl FnOnce(rpc::Request) -> rpc::Response,
) {
    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
    let request = rpc::recv_request(&mut stream).await.unwrap();
    let response = handle(request);
    rpc::send_response(&mut sink, &response).await.unwrap();
}

async fn respond<L: commonware_runtime::Listener>(
    listener: &mut L,
    handle: impl FnOnce(operator_rpc::OperatorRequest) -> rpc::Response,
) {
    respond_rpc(listener, |request| {
        handle(operator_rpc::decode_request(request).unwrap())
    })
    .await;
}

/// Serves one request against the real operator.
async fn relay<L: commonware_runtime::Listener>(listener: &mut L, operator: &mut Operator) {
    respond(listener, |request| {
        operator_rpc::handle_decoded(operator, request)
    })
    .await;
}

/// Refuses one request: the operator is up but answers with an error. Returns
/// the refused request so the test can pin what the wallet asked for.
async fn refuse<L: commonware_runtime::Listener>(
    listener: &mut L,
) -> operator_rpc::OperatorRequest {
    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
    let request =
        operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap()).unwrap();
    rpc::send_response(&mut sink, &rpc::error_response("operator refuses".into()))
        .await
        .unwrap();
    request
}

/// Accepts one send against the real operator with the response lost,
/// returning the committed acceptance.
async fn accept_and_drop<L: commonware_runtime::Listener>(
    listener: &mut L,
    operator: &mut Operator,
) -> operator_rpc::AcceptedBatchResponse {
    let (_, _sink, mut stream) = listener.accept().await.unwrap();
    let request = rpc::recv_request(&mut stream).await.unwrap();
    let operator_rpc::OperatorRequest::AcceptSend(request) =
        operator_rpc::decode_request(request).unwrap()
    else {
        panic!("expected the staged send");
    };
    operator
        .accept_send(request.authorization, request.entries)
        .unwrap()
        .into_accepted()
        .into()
}

/// Countersigns one payer authorization as the scripted operator, producing the
/// dual-signed acknowledgment the wire carries.
fn countersign(authorization: &SendAuthorization<Key, Digest>, operator: &Wallet) -> Ack {
    let encoded = authorization.body().encode();
    Ack::from_raw_unchecked(
        authorization.body().clone(),
        authorization.payer_signature().clone(),
        operator
            .signer()
            .sign(VECTOR_ACK_SIGNATURE_NAMESPACE, &encoded),
    )
}

/// Issues the acceptance a scripted operator returns for one submitted batch: the deltas
/// merge into `prior` (the payer's cumulative vector before the batch), the merged root
/// must be the acknowledged root, and each credited entry opens under it.
fn issue_acceptance(
    operator: &Wallet,
    prior: &[OutEntry<Key>],
    authorization: &SendAuthorization<Key, Digest>,
    entries: &[Entry],
) -> Acceptance {
    let mut merged = prior.to_vec();
    for entry in entries {
        match merged.binary_search_by(|edge| edge.recipient.cmp(&entry.recipient)) {
            Ok(position) => {
                merged[position].cumulative += entry.amount;
                merged[position].count += 1;
            }
            Err(position) => merged.insert(
                position,
                OutEntry {
                    recipient: entry.recipient.clone(),
                    cumulative: entry.amount,
                    count: 1,
                },
            ),
        }
    }
    let body = authorization.body();
    let vector = OutVector::new(body.epoch(), body.payer().clone(), merged).unwrap();
    assert_eq!(
        vector.root::<Sha256, Digest>().unwrap(),
        body.send_root(),
        "the scripted operator merged another vector view"
    );
    let opened = entries
        .iter()
        .map(|entry| {
            let OutTipLookup::Present {
                cumulative,
                count,
                opening,
            } = vector.lookup::<Sha256, Digest>(&entry.recipient).unwrap()
            else {
                panic!("every credited recipient is in the merged vector");
            };
            AcceptedEntry {
                recipient: entry.recipient.clone(),
                cumulative,
                count,
                opening,
            }
        })
        .collect();
    Acceptance {
        ack: countersign(authorization, operator),
        entries: opened,
    }
}

/// A dual-signed receipt crediting `recipient` with one payment of `amount` from `payer`
/// at sequence one under `context`, signed by the compiled default operator authority.
fn issued_receipt(
    context: &PaymentContext<Key, Digest>,
    payer: &Wallet,
    recipient: &Key,
    amount: u64,
) -> Receipt {
    let vector = OutVector::new(
        context.epoch(),
        payer.public_key(),
        vec![OutEntry {
            recipient: recipient.clone(),
            cumulative: amount,
            count: 1,
        }],
    )
    .unwrap();
    let body = VectorSendBody::new(
        context,
        payer.public_key(),
        1,
        amount,
        vector.root::<Sha256, Digest>().unwrap(),
    );
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let ack = Ack::sign_by_authorities(body, payer.signer(), protocol.operator());
    let OutTipLookup::Present { opening, .. } = vector.lookup::<Sha256, Digest>(recipient).unwrap()
    else {
        panic!("the issued entry is present by construction");
    };
    Receipt {
        ack,
        recipient: recipient.clone(),
        cumulative: amount,
        count: 1,
        opening,
    }
}

fn accepted(outcome: PaymentOutcome) -> operator_rpc::AcceptedBatchResponse {
    match outcome {
        PaymentOutcome::Accepted(payment) => *payment,
        PaymentOutcome::CommittedUnheld { epoch, total } => {
            panic!("epoch {epoch} payment for {total} committed without receipts")
        }
    }
}

fn accept_response(accepted: operator_rpc::AcceptedBatchResponse) -> Bytes {
    operator_rpc::AcceptSendResponse::Accepted(accepted).encode()
}

/// A scripted corrective rejection claiming `cumulative_debit`. Every scripted use claims
/// an endpoint the wallet refuses to adopt, so the served sequence and vector are empty.
fn stale_response(context: &PaymentContext<Key, Digest>, cumulative_debit: u64) -> Bytes {
    operator_rpc::AcceptSendResponse::Stale {
        context: context.clone(),
        cumulative_debit,
        seq: 0,
        entries: Vec::new(),
    }
    .encode()
}

/// Opens a withdrawal-claim intent directly, standing in for a completed withdrawal.
fn open_withdrawal_intent(agent: &mut Agent) {
    agent.store.open_withdrawal_claim().unwrap();
    agent.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
        evidence: None,
        result: None,
    });
}

/// The four-identity genesis account state the chain certifies at its root.
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
    AccountCache::new::<Sha256>(leaves).unwrap()
}

/// A scripted payment head over the certified genesis root: the served state
/// is operator-claimed display data, and the opening is the wallet's genuine
/// genesis row.
fn payment_head_response(
    context: PaymentContext<Key, Digest>,
    state: AccountState,
) -> operator_rpc::PaymentHeadResponse {
    let account = wallets()[0].public_key();
    let cache = genesis_cache();
    operator_rpc::PaymentHeadResponse {
        context,
        state,
        root: cache.root(),
        opening: cache.opening(&account).unwrap(),
    }
}

#[test]
fn payment_debit_is_local_and_advances_only_after_a_verified_receipt() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let impostor = Wallet::from_seed("impostor", 1_001);
        let payment_context = registered_context(&control).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server_context = payment_context.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            let payment_context = server_context;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            cumulative_debit: 10_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;

            let mut first_payment = None;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("payment retry unexpectedly requested another head");
                };
                assert_eq!(request.authorization.body().cumulative_debit(), 7);
                let genuine =
                    issue_acceptance(&operator, &[], &request.authorization, &request.entries);

                // The forged acceptance countersigns the exact acknowledged body with an
                // impostor key, so only signature verification stands between the wallet
                // and recording it.
                let forged = Acceptance {
                    ack: countersign(&request.authorization, &impostor),
                    entries: genuine.entries.clone(),
                };
                first_payment = Some((request.authorization, request.entries, genuine));
                rpc::Response::Success {
                    body: accept_response(operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 1,
                        total: 7,
                        acceptance: forged,
                    }),
                }
            })
            .await;
            let (first_authorization, first_entries, first_payment) = first_payment.unwrap();

            // The retry resubmits the exact staged bytes directly, with no head read:
            // the operator's typed reply adjudicates the resubmission.
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("live retry unexpectedly skipped its resubmission");
                };
                assert_eq!(request.authorization, first_authorization);
                assert_eq!(request.entries, first_entries);
                rpc::Response::Success {
                    body: accept_response(operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 1,
                        total: 7,
                        acceptance: first_payment.clone(),
                    }),
                }
            })
            .await;

            // The second payment signs from local state alone: the cached context and
            // the wallet's own endpoint and vector state suffice, so no head read
            // precedes the send.
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the second signed send");
                };
                assert_eq!(request.authorization.body().cumulative_debit(), 10);
                let prior = first_payment
                    .entries
                    .iter()
                    .map(|entry| OutEntry {
                        recipient: entry.recipient.clone(),
                        cumulative: entry.cumulative,
                        count: entry.count,
                    })
                    .collect::<Vec<_>>();
                let acceptance =
                    issue_acceptance(&operator, &prior, &request.authorization, &request.entries);
                rpc::Response::Success {
                    body: accept_response(operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 2,
                        total: 3,
                        acceptance,
                    }),
                }
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        let rejected = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{rejected:#}").contains("verify operator receipt"));
        assert_eq!(agent.receipt_count(), 0);

        // Every recorded acceptance passed the certified anchor gate for the
        // registered epoch.
        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.entries[0].cumulative, 7);
        assert_eq!(agent.receipt_count(), 1);
        assert_eq!(
            payment.acceptance.ack.body().anchor(),
            payment_context.anchor()
        );

        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.total, 3);
        assert_eq!(payment.acceptance.entries[0].cumulative, 10);
        assert_eq!(agent.receipt_count(), 2);
        operator_server.await.unwrap();
    });
}

#[test]
fn stale_uncommitted_payment_is_abandoned_on_the_finalized_endpoint_proof() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let cut = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The staged send never reaches the operator: the head is served and
        // the accept request is dropped, so the send stays uncommitted.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let (_, _sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            assert!(matches!(
                operator_rpc::decode_request(request).unwrap(),
                operator_rpc::OperatorRequest::AcceptSend(_)
            ));
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let pending = agent.pending_payment.as_ref().unwrap();
        assert_eq!(pending.authorization.body().epoch(), cut.epoch());
        assert_eq!(agent.cumulative_debit, 0);
        let (mut listener, mut operator) = staging.await.unwrap();

        // The epoch is cut and certifiably finalized with unrelated work, so
        // the wallet's send is provably excluded from the finalized endpoint.
        operator.pay(1, 2, 1).unwrap();
        let result = operator.complete_close(2).unwrap();
        finalize(&control, &result).await;
        let live = register(&control, &mut operator).await;
        assert_eq!(live.epoch(), 1);

        // The retry resubmits the staged bytes and earns a corrective rejection
        // whose claimed endpoint is not the wallet's own, so the wallet refuses to
        // adopt it and routes through settlement-anchored resolution instead.
        let live_context = live.clone();
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
                rpc::Response::Success {
                    body: stale_response(&live_context, 3),
                }
            })
            .await;

            // Resolution reads the real head against the certified finalized
            // root: the verified opening still carries the prior endpoint, so
            // the wallet abandons on the chain's proof alone, then re-stages
            // from the re-anchored cache and this send commits for real.
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
        });

        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(payment.acceptance.entries[0].cumulative, 7);
        assert_eq!(payment.acceptance.ack.body().cumulative_debit(), 7);
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.cache.as_ref().unwrap().context.epoch(), live.epoch());
        resolution.await.unwrap();
    });
}

#[test]
fn committed_payment_resolves_from_the_finalized_endpoint_without_a_verdict() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let committed = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The operator commits the batch for real, but its response is lost
        // before the wallet records it.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let recorded = accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator, recorded)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        assert_eq!(
            agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .body()
                .epoch(),
            0
        );
        let (mut listener, mut operator, recorded) = staging.await.unwrap();

        // The committed send rides the certifiably finalized close, so the
        // finalized endpoint carries the staged successor value.
        let result = operator.complete_close(3).unwrap();
        finalize(&control, &result).await;

        // The retry resubmits the staged bytes and earns a corrective
        // rejection claiming the committed endpoint, which is not the endpoint
        // this wallet stands at (a lossy front: the live operator would
        // simply replay the committed batch). Such a claim is never adopted
        // blindly: the wallet resolves from the certified finalized root and
        // only fetches the receipts through the accepted-batch recovery.
        let live = operator
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;
        let expected_ack = recorded.acceptance.ack.clone();
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("the retry did not resubmit the staged bytes");
                };
                assert_eq!(request.authorization.body(), expected_ack.body());
                rpc::Response::Success {
                    body: stale_response(&live, 7),
                }
            })
            .await;
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptedBatch(request) = request else {
                    panic!("the receipts fetch did not name the exact staged bytes");
                };
                assert_eq!(request.authorization.body(), expected_ack.body());
                operator_rpc::handle_decoded(
                    &mut operator,
                    operator_rpc::OperatorRequest::AcceptedBatch(request),
                )
            })
            .await;
        });

        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, committed.epoch());
        assert_eq!(payment.acceptance.entries[0].cumulative, 7);
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.pending_payment.is_none());
        resolution.await.unwrap();
    });
}

#[test]
fn unfinalized_staged_epoch_keeps_resolution_undecidable() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let cut = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The staged send never reaches the operator, so it stays uncommitted.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let (_, _sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            assert!(matches!(
                operator_rpc::decode_request(request).unwrap(),
                operator_rpc::OperatorRequest::AcceptSend(_)
            ));
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let staged = agent
            .pending_payment
            .as_ref()
            .unwrap()
            .authorization
            .clone();
        assert_eq!(staged.body().epoch(), cut.epoch());
        let (mut listener, mut operator) = staging.await.unwrap();

        // The epoch is cut locally but the chain never admits its close, so
        // no certified finalization covers the staged epoch.
        operator.pay(1, 2, 1).unwrap();
        let _unadmitted = operator.complete_close(4).unwrap();
        let live = operator
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;

        // The retry earns a corrective rejection claiming an endpoint the
        // wallet does not recognize, so it resolves from the chain. Nothing
        // has certifiably finalized, so commitment is not decidable and
        // everything is kept.
        let live_context = live.clone();
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
                rpc::Response::Success {
                    body: stale_response(&live_context, 7),
                }
            })
            .await;
            relay(&mut listener, &mut operator).await;
        });

        // An undecidable resolution must retry, never abandon: the exact staged send
        // stays pending and the debit endpoint does not advance.
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("not yet decidable"));
        assert_eq!(
            agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .encode(),
            staged.encode()
        );
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        resolution.await.unwrap();
    });
}

#[test]
fn finalized_endpoint_commits_without_receipts_when_the_fetch_fails() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The operator commits the batch but its response is lost.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let recorded = accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator, recorded)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let (mut listener, mut operator, _recorded) = staging.await.unwrap();

        // The committed send rides the certifiably finalized close.
        let result = operator.complete_close(5).unwrap();
        finalize(&control, &result).await;
        let live = register(&control, &mut operator).await;

        // The retry earns a corrective naming the committed endpoint (a lossy
        // front: the live operator would replay the committed batch), and the
        // operator then serves no batch for the send: only the certified
        // finalized endpoint proves the commitment, and the carve-out lets
        // the next send proceed with the receipts unheld.
        let stale = operator
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
                rpc::Response::Success {
                    body: stale_response(&stale, 7),
                }
            })
            .await;
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptedBatch(_)
                ));
                rpc::Response::Success {
                    body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                }
            })
            .await;
            (listener, operator)
        });
        let outcome = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
        ));
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 0);
        assert!(agent.pending_payment.is_none());
        drop(agent);
        let (mut listener, mut operator) = resolution.await.unwrap();

        // The unheld commit is durable: the endpoint survives restart without any
        // retained receipts, and the next send debits its exact successor from
        // local state alone.
        let successor = context.child("successor").spawn(move |_| async move {
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the successor send");
                };
                assert_eq!(request.authorization.body().cumulative_debit(), 10);
                operator_rpc::handle_decoded(
                    &mut operator,
                    operator_rpc::OperatorRequest::AcceptSend(request),
                )
            })
            .await;
        });
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 0);
        assert!(recovered.pending_payment.is_none());
        let payment = accepted(
            recovered
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.total, 3);
        assert_eq!(payment.acceptance.entries[0].cumulative, 3);
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(recovered.cumulative_debit, 10);
        successor.await.unwrap();
    });
}

#[test]
fn forged_resolution_opening_fails_verification_and_retries() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let recorded = accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator, recorded)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let staged = agent
            .pending_payment
            .as_ref()
            .unwrap()
            .authorization
            .clone();
        let (mut listener, mut operator, _recorded) = staging.await.unwrap();

        let result = operator.complete_close(6).unwrap();
        finalize(&control, &result).await;
        let alice = wallets()[0].public_key();

        // The retry earns a corrective naming the committed endpoint (a lossy
        // front: the live operator would replay the committed batch), and the
        // resolution head serves the wallet's row under the certified
        // finalized root but with a corrupted Merkle proof, which must be
        // rejected before anything is concluded.
        let stale = operator.payment_head(&alice).unwrap().context;
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
                rpc::Response::Success {
                    body: stale_response(&stale, 7),
                }
            })
            .await;
            let mut head = operator.payment_head(&alice).unwrap();
            respond(&mut listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                head.opening.proof.proof.leaf_count = 2;
                head.opening
                    .proof
                    .proof
                    .siblings
                    .push(Sha256::hash(&[b"invalid-payer-opening"]));
                rpc::Response::Success {
                    body: operator_rpc::PaymentHeadResponse {
                        context: head.context.clone(),
                        state: head.state,
                        root: head.root,
                        opening: head.opening.clone(),
                    }
                    .encode(),
                }
            })
            .await;
        });

        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("verify payer state opening"));
        assert_eq!(
            agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .encode(),
            staged.encode()
        );
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        resolution.await.unwrap();
    });
}

/// The registration singleton keeps naming an epoch after its close is
/// admitted, until finalization retires it. Inside that window the staged
/// epoch is dead (the close is fixed), so a resolution that cannot read the
/// operator's head must not take the record as proof of liveness and resubmit
/// the dead bytes: the admitted mark makes it wait for finalization, and the
/// finalized endpoint then decides from the slice holders' opening alone.
#[test]
fn admitted_staged_epoch_is_not_live_without_the_operator_head() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let admitted = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The operator commits the batch but its response is lost.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let staged = agent
            .pending_payment
            .as_ref()
            .unwrap()
            .authorization
            .clone();
        assert_eq!(staged.body().epoch(), admitted.epoch());
        let (mut listener, mut operator) = staging.await.unwrap();

        // The close carrying the send is admitted but not finalized, and no
        // successor is registered: the registration singleton still names the
        // staged epoch and anchor, now marked admitted.
        let result = operator.complete_close(8).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        let registration = registration_record(&control).await;
        assert_eq!(registration.epoch, admitted.epoch());
        assert_eq!(registration.anchor, *admitted.anchor());
        assert!(registration.admitted.is_some());
        assert!(status(&control).await.last_finalized.is_none());

        // The operator goes dark for everything but the corrective: each retry
        // earns a rejection naming the committed endpoint (a lossy front) and
        // the head is refused, so liveness is decided from the chain alone. No
        // send follows a refused head, because an admitted epoch is not live:
        // the next request after each head is the second retry's corrective
        // and then the receipts fetch, never the staged bytes again.
        let stale = operator
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;
        let expected = staged.clone();
        let resolution = context.child("resolution").spawn(move |_| async move {
            for _ in 0..2 {
                let stale = stale.clone();
                let expected = expected.clone();
                respond(&mut listener, move |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("the retry did not resubmit the staged bytes");
                    };
                    assert_eq!(request.authorization.body(), expected.body());
                    rpc::Response::Success {
                        body: stale_response(&stale, 7),
                    }
                })
                .await;
                assert!(matches!(
                    refuse(&mut listener).await,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
            }
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::AcceptedBatch(_)
            ));
        });

        // Admitted but unfinalized, the commitment is not yet decidable: the
        // exact bytes stay pending and the endpoint does not move.
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("not yet decidable"),
            "{error:#}"
        );
        assert_eq!(
            agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .encode(),
            staged.encode()
        );
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);

        // Finalization retires the registration and releases the close's
        // dealing, so the finalized head opens from the holders only once the
        // successor close is admitted: its predecessor state is the same root,
        // retained through its own window.
        let deadline = result.epoch_context.challenge_deadline();
        let height = control.advance(0).await;
        if height <= deadline {
            control.advance(deadline - height + 1).await;
        }
        assert!(
            control
                .record(registration_key(&deployment()))
                .await
                .is_none()
        );
        register(&control, &mut operator).await;
        operator.pay(1, 2, 1).unwrap();
        let successor = operator.complete_close(9).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&successor)),
        )
        .await;
        let head = status(&control).await;
        assert_eq!(head.last_finalized, Some(admitted.epoch()));
        assert_eq!(head.state_root, result.finalized.successor_root);

        // The holder-served endpoint carries the staged successor, so the send
        // committed, and the refused receipts fetch leaves it unheld.
        let outcome = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
        ));
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 0);
        assert!(agent.pending_payment.is_none());
        assert!(
            agent
                .store
                .recovery_opening(&head.state_root)
                .unwrap()
                .is_some()
        );
        resolution.await.unwrap();
    });
}

/// Without the operator's head the signing context is the chain's
/// registration, which keeps naming an epoch after its close is admitted
/// until the successor registers or finalization retires it. That epoch is
/// dead (the close is fixed), so a fresh send is never staged under it: the
/// wallet refuses until the successor registers, which the chain allows inside
/// the window, and then signs under the successor over the same genesis root.
#[test]
fn admitted_registration_is_not_stageable_without_the_operator_head() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let admitted = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The close is admitted but not finalized: the registration singleton
        // still names its epoch, now marked admitted, and the certified head is
        // still the genesis root.
        operator.pay(1, 2, 1).unwrap();
        let result = operator.complete_close(10).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        let registration = registration_record(&control).await;
        assert_eq!(registration.epoch, admitted.epoch());
        assert!(registration.admitted.is_some());
        assert!(status(&control).await.last_finalized.is_none());

        // The head is refused, so the wallet has only the chain's registration,
        // and an admitted registration is no live context: nothing is staged.
        // The listener goes with the task, so a send staged in error is refused
        // at the wire instead of waiting on a listener nobody serves.
        let refusing = context.child("refusing").spawn(move |_| async move {
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::PaymentHead(_)
            ));
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no live payment context"),
            "{error:#}"
        );
        assert!(agent.pending_payment.is_none());
        assert!(agent.cache.is_none());
        assert_eq!(agent.cumulative_debit, 0);
        refusing.await.unwrap();

        // The successor registers inside the window. The head is still
        // refused, and the wallet signs under the successor context with the
        // holders' genesis opening as its floor, which the operator accepts.
        let live = register(&control, &mut operator).await;
        assert_ne!(live.epoch(), admitted.epoch());
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let expected = live.clone();
        let paying = context.child("paying").spawn(move |_| async move {
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::PaymentHead(_)
            ));
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(send) = &request else {
                    panic!("the stage did not submit a send");
                };
                assert_eq!(send.authorization.body().epoch(), expected.epoch());
                assert_eq!(send.authorization.body().anchor(), expected.anchor());
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });
        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(agent.cumulative_debit, 7);
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.cache.as_ref().unwrap().context, live);
        paying.await.unwrap();
    });
}

/// A resolution decided from the slice holders' opening, with the operator's
/// head refused, proves the staged context cut but is served no live successor
/// to re-cache. The cached signing context is that cut one, so it goes with the
/// abandoned send: the fresh stage asks the chain instead, which refuses while
/// the registered successor is admitted and signs under the next epoch once it
/// registers. No send is ever signed under the dead epoch.
#[test]
fn holder_served_abandonment_drops_the_cut_signing_context() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let cut = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The head is served and cached, and the staged send never reaches the
        // operator, so it stays uncommitted.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let (_, _sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            assert!(matches!(
                operator_rpc::decode_request(request).unwrap(),
                operator_rpc::OperatorRequest::AcceptSend(_)
            ));
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        assert_eq!(agent.cache.as_ref().unwrap().context, cut);
        let (mut listener, mut operator) = staging.await.unwrap();

        // The staged epoch finalizes with unrelated work, excluding the send,
        // and the successor close is admitted but not finalized: the holders
        // open the finalized root from its predecessor state, and the
        // registration names the admitted successor, so no epoch is live.
        operator.pay(1, 2, 1).unwrap();
        let result = operator.complete_close(11).unwrap();
        finalize(&control, &result).await;
        register(&control, &mut operator).await;
        operator.pay(1, 2, 1).unwrap();
        let successor = operator.complete_close(12).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&successor)),
        )
        .await;
        assert!(registration_record(&control).await.admitted.is_some());
        let finalized_root = status(&control).await.state_root;
        assert_eq!(finalized_root, result.finalized.successor_root);

        // The retry earns a corrective claiming an unrecognized endpoint and
        // the head is refused, so the holders' opening decides: the send is
        // abandoned. The stage that follows must not sign under the cached cut
        // context. With the head refused again it asks the chain, whose
        // admitted registration is no live context, so nothing is staged. The
        // listener goes with the task, so a send staged in error is refused at
        // the wire instead of waiting on a listener nobody serves.
        let stale = operator
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
                rpc::Response::Success {
                    body: stale_response(&stale, 3),
                }
            })
            .await;
            for _ in 0..2 {
                assert!(matches!(
                    refuse(&mut listener).await,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
            }
        });
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no live payment context"),
            "{error:#}"
        );
        assert!(agent.pending_payment.is_none());
        assert!(agent.cache.is_none());
        assert_eq!(agent.cumulative_debit, 0);
        assert!(
            agent
                .store
                .recovery_opening(&finalized_root)
                .unwrap()
                .is_some()
        );
        resolution.await.unwrap();

        // The next epoch registers inside the successor's window. The head is
        // still refused, and the fresh send signs under the new epoch and
        // anchor with the holders' finalized opening as its floor.
        let live = register(&control, &mut operator).await;
        assert_ne!(live.epoch(), cut.epoch());
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let expected = live.clone();
        let paying = context.child("paying").spawn(move |_| async move {
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::PaymentHead(_)
            ));
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(send) = &request else {
                    panic!("the stage did not submit a send");
                };
                assert_eq!(send.authorization.body().epoch(), expected.epoch());
                assert_eq!(send.authorization.body().anchor(), expected.anchor());
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });
        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(agent.cumulative_debit, 7);
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.cache.as_ref().unwrap().context, live);
        paying.await.unwrap();
    });
}

#[test]
fn finalized_endpoint_below_the_committed_endpoint_is_reported_not_healed() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;

        // Two operators share one genesis and one registered epoch-0 context:
        // the honest one acknowledges the wallet's sends, and the Byzantine
        // one finalizes a close omitting them.
        let mut honest = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut byzantine = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut honest).await;
        let record = registration_record(&control).await;
        byzantine.adopt_registration(&record).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The first payment completes and holds its receipt. The second is
        // acknowledged but its response is lost.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut honest).await;
            relay(&mut listener, &mut honest).await;
            let dropped = accept_and_drop(&mut listener, &mut honest).await;
            (listener, honest, dropped)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.entries[0].cumulative, 7);
        assert_eq!(agent.cumulative_debit, 7);
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 3)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let (mut listener, _honest, _dropped) = staging.await.unwrap();

        // The Byzantine close finalizes with only unrelated work, leaving the
        // certified endpoint below the wallet's committed endpoint.
        byzantine.pay(1, 2, 1).unwrap();
        let result = byzantine.complete_close(7).unwrap();
        finalize(&control, &result).await;
        let live = byzantine
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;

        for pass in 0..2 {
            let live_context = live.clone();
            let mut server = byzantine;
            let resolution = context.child("resolution").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                    rpc::Response::Success {
                        body: stale_response(&live_context, 0),
                    }
                })
                .await;
                relay(&mut listener, &mut server).await;
                (listener, server)
            });

            // The finalized endpoint (0) matches neither the committed endpoint (7)
            // nor the staged successor (10): report loudly, never heal.
            let error = agent
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("omitted an acknowledged send"),
                "unexpected error on pass {pass}: {error:#}"
            );
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 1);
            assert!(agent.pending_payment.is_some());
            let staged = agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .encode();
            (listener, byzantine) = resolution.await.unwrap();

            // The restarted wallet reports the same contradiction from its
            // durable state.
            drop(agent);
            agent = Agent::open(database.path(), 0).unwrap();
            assert_eq!(agent.cumulative_debit, 7);
            assert_eq!(agent.receipt_count(), 1);
            assert_eq!(
                agent
                    .pending_payment
                    .as_ref()
                    .unwrap()
                    .authorization
                    .encode(),
                staged
            );
        }
    });
}

#[test]
fn deterministically_rejected_sends_are_never_staged() {
    deterministic::Runner::default().start(|context| async move {
        let (_control, mut chain) = chain(&context).await;
        let head_context =
            PaymentContext::new(Sha256::hash(&[b"never-staged-context"]), 0, operator_key());
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        head_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();

        // A self-payment is refused before any request is issued.
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(0, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("self-payments"));
        assert!(agent.pending_payment.is_none());

        // An unaffordable batch is refused by the live-balance precheck after
        // the head read, before anything is staged.
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 60), (2, 41)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("insufficient available balance"));
        assert!(agent.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

/// Serves one scripted acceptance at the expected endpoint, merging the request's deltas
/// into `prior` (the payer's cumulative vector before the batch).
async fn respond_acceptance<L: commonware_runtime::Listener>(
    listener: &mut L,
    operator: &Wallet,
    context: &PaymentContext<Key, Digest>,
    endpoint: u64,
    prior: Vec<OutEntry<Key>>,
) {
    respond(listener, |request| {
        let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
            panic!("expected a signed send");
        };
        assert_eq!(request.authorization.body().epoch(), context.epoch());
        assert_eq!(request.authorization.body().cumulative_debit(), endpoint);
        let total = request
            .entries
            .iter()
            .map(|entry| entry.amount)
            .sum::<u64>();
        let acceptance =
            issue_acceptance(operator, &prior, &request.authorization, &request.entries);
        rpc::Response::Success {
            body: accept_response(operator_rpc::AcceptedBatchResponse {
                epoch: context.epoch(),
                sequence: request.authorization.body().seq(),
                total,
                acceptance,
            }),
        }
    })
    .await;
}

/// The single Alice-to-Bob cumulative edge at `(cumulative, count)`, the prior vector the
/// scripted payment sequences advance through.
fn bob_edge(cumulative: u64, count: u64) -> Vec<OutEntry<Key>> {
    vec![OutEntry {
        recipient: wallets()[1].public_key(),
        cumulative,
        count,
    }]
}

#[test]
fn steady_state_payments_sign_from_local_state_without_head_reads() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = registered_context(&control).await;
        let baseline = control.counts().await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server_context = payment_context.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // Only the fresh wallet's first payment reads the head. Every request after
            // it must be an acceptance: a head read on the steady-state path would fail
            // these method assertions.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        server_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond_acceptance(&mut listener, &operator, &server_context, 7, Vec::new()).await;
            respond_acceptance(
                &mut listener,
                &operator,
                &server_context,
                10,
                bob_edge(7, 1),
            )
            .await;
            respond_acceptance(
                &mut listener,
                &operator,
                &server_context,
                12,
                bob_edge(10, 2),
            )
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(agent.cumulative_debit, 10);
        drop(agent);

        // The cache is durable, so the restarted wallet also signs locally.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        accepted(
            recovered
                .pay(&context, &mut chain, operator_address, &[(1, 2)])
                .await
                .unwrap(),
        );
        assert_eq!(recovered.cumulative_debit, 12);
        assert_eq!(recovered.receipt_count(), 3);
        operator_server.await.unwrap();

        // The steady-state chain footprint is exactly one status read for the
        // fresh wallet's head stage and one certified anchor confirmation per
        // recorded acceptance, with no submissions.
        let (reads, submissions) = control.counts().await;
        assert_eq!(reads - baseline.0, 4);
        assert_eq!(submissions - baseline.1, 0);
    });
}

#[test]
fn fresh_wallet_falls_back_to_one_head_read_and_caches_the_context() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = registered_context(&control).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server_context = payment_context.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        server_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond_acceptance(&mut listener, &operator, &server_context, 7, Vec::new()).await;
        });

        let mut agent = Agent::new(0).unwrap();
        assert!(agent.cache.is_none());
        accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );

        // The single head read cached the served context and its verified floor, so
        // later payments have everything they need in local SQL.
        let cache = agent.cache.as_ref().unwrap();
        assert_eq!(cache.context, payment_context);
        assert_eq!(cache.epoch, payment_context.epoch());
        assert_eq!(cache.root, genesis_cache().root());
        assert!(agent.store.recovery_opening(&cache.root).unwrap().is_some());
        operator_server.await.unwrap();
    });
}

#[test]
fn epoch_roll_corrective_rejection_teaches_the_new_context() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let old = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();

        // The first payment stages from the head and commits for real.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(agent.cumulative_debit, 7);
        let (mut listener, mut operator) = staging.await.unwrap();

        // The epoch rolls: the close finalizes certifiably and the successor
        // registers, so the operator's live context moved on.
        let result = operator.complete_close(11).unwrap();
        finalize(&control, &result).await;
        let live = register(&control, &mut operator).await;
        assert_eq!(live.epoch(), 1);

        // The locally signed send earns the real corrective rejection naming
        // the live context and the payer's own endpoint, the wallet adopts it
        // and retries the same intent once, and the next payment stays local.
        let rolling = context.child("rolling").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
        });
        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(agent.cumulative_debit, 10);
        assert!(agent.pending_payment.is_none());

        // Adoption moved the signing context forward and kept the verified floor.
        let cache = agent.cache.as_ref().unwrap();
        assert_eq!(cache.context, live);
        assert_eq!(cache.epoch, old.epoch());

        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 2)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(agent.cumulative_debit, 12);
        assert_eq!(agent.receipt_count(), 3);
        rolling.await.unwrap();
    });
}

#[test]
fn unaffordable_by_local_view_is_refused_before_staging() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = registered_context(&control).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server_context = payment_context.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        server_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond_acceptance(&mut listener, &operator, &server_context, 7, Vec::new()).await;

            // The local floor cannot prove affordability for the oversized send, so
            // the wallet confirms against one live head read, which refuses it before
            // anything is staged.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        server_context.clone(),
                        AccountState {
                            balance: 93,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;

            // Nothing was staged, so the wallet is not wedged: an affordable payment
            // still signs from local state.
            respond_acceptance(
                &mut listener,
                &operator,
                &server_context,
                10,
                bob_edge(7, 1),
            )
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );

        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 200)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("insufficient available balance"));
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.cumulative_debit, 7);

        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.total, 3);
        assert_eq!(payment.acceptance.entries[0].cumulative, 10);
        assert_eq!(agent.cumulative_debit, 10);
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_deadline_caps_at_the_clock_horizon() {
    assert_eq!(
        withdrawal_deadline(7),
        7 + crate::protocol::WITHDRAWAL_HORIZON
    );
    assert_eq!(withdrawal_deadline(u64::MAX - 20), u64::MAX);
}

/// A client whose one validator address answers nothing, for flows that must
/// fail before any chain interaction.
fn dead_client(context: &deterministic::Context) -> Client {
    let mut identity_rng = context.child("identity_rng");
    Client::new(
        &harness::identity(&mut identity_rng),
        deployment(),
        vec![SocketAddr::from(([127, 0, 0, 1], 9_601))],
        context.child("client_rng"),
    )
    .unwrap()
}

#[test]
fn deposit_response_loss_preserves_exact_retry_until_recorded() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut agent = Agent::new(0).unwrap();

        // The first attempt stages durably, then loses the chain: the
        // outcome is unclassifiable, so the staged event must survive.
        let mut dead = dead_client(&context);
        let error = agent.deposit(&context, &mut dead, 7).await.unwrap_err();
        assert!(format!("{error:#}").contains("record settlement deposit"));
        let event = agent.pending_deposit.clone().unwrap();
        assert_eq!(agent.deposit_nonce, 0);

        // The retry replays the exact staged event and completes on the
        // certified custody record: no second custody moves.
        let applied = agent.deposit(&context, &mut chain, 7).await.unwrap();
        assert_eq!(applied, event);
        assert!(agent.pending_deposit.is_none());
        assert_eq!(agent.deposit_nonce, 1);
        assert_eq!(status(&control).await.custody, 407);
    });
}

#[test]
fn deposit_nonce_overflow_precedes_custody() {
    deterministic::Runner::default().start(|context| async move {
        let mut chain = dead_client(&context);
        let mut agent = Agent::new(0).unwrap();
        agent.deposit_nonce = u64::MAX;
        let error = agent.deposit(&context, &mut chain, 7).await.unwrap_err();
        assert!(format!("{error:#}").contains("deposit nonce overflow"));
        assert!(agent.pending_deposit.is_none());
    });
}

#[test]
fn foreign_bound_deposit_id_discards_the_staged_event() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut agent = Agent::new(0).unwrap();
        let account = agent.account();

        // A conflicting event certifiably consumes the id the wallet's first
        // deposit would derive, so the wallet's staged bytes can never take
        // custody.
        let id = Sha256::hash(&[
            DEPOSIT_ID_NAMESPACE,
            account.as_ref(),
            &0_u64.to_be_bytes(),
            &7_u64.to_be_bytes(),
        ]);
        applied(
            &control,
            &SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                deployment: deployment(),
                event: DepositEvent {
                    id,
                    account: account.clone(),
                    amount: 9,
                },
            }),
        )
        .await;
        assert_eq!(status(&control).await.custody, 409);

        // The wallet observes the foreign binding on the certified record
        // and discards the staged event instead of retrying it forever.
        let error = agent.deposit(&context, &mut chain, 7).await.unwrap_err();
        assert!(format!("{error:#}").contains("certifiably bound to another event"));
        assert!(agent.pending_deposit.is_none());
        assert_eq!(status(&control).await.custody, 409);
    });
}

#[test]
fn withdrawal_response_loss_and_wrong_ack_preserve_one_exact_request() {
    deterministic::Runner::default().start(|context| async move {
        let (_control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_OPENING);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;

            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let first = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(first.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
            let first_body = first.body.clone();
            let first = operator_rpc::decode_request(first).unwrap();
            assert!(matches!(
                operator_rpc::handle_decoded(&mut operator, first),
                rpc::Response::Success { .. }
            ));
            drop(sink);

            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                assert_eq!(request.body, first_body);
                let request = operator_rpc::decode_request(request).unwrap();
                assert!(matches!(
                    operator_rpc::handle_decoded(&mut operator, request),
                    rpc::Response::Success { .. }
                ));
                rpc::Response::Success {
                    body: operator_rpc::WithdrawalAck {
                        epoch: 0,
                        digest: Sha256::hash(&[b"another-withdrawal"]),
                    }
                    .encode(),
                }
            })
            .await;

            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                assert_eq!(request.body, first_body);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });

        let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let mut agent = Agent::new(0).unwrap();
        let first = agent
            .withdraw(&context, &mut chain, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, error } = first else {
            panic!("lost operator response unexpectedly applied withdrawal");
        };
        assert!(format!("{error:#}").contains("apply operator withdrawal"));
        assert!(agent.pending_withdrawal.is_some());

        let wrong_ack = agent
            .withdraw(&context, &mut chain, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed {
            request: retained,
            error,
        } = wrong_ack
        else {
            panic!("wrong operator acknowledgement cleared withdrawal");
        };
        assert_eq!(retained, request);
        assert!(format!("{error:#}").contains("another withdrawal"));
        assert!(agent.pending_withdrawal.is_some());

        let retry = agent
            .withdraw(&context, &mut chain, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Applied {
            epoch,
            request: applied,
        } = retry
        else {
            panic!("exact withdrawal retry was not acknowledged");
        };
        assert_eq!(epoch, 0);
        assert_eq!(applied, request);
        assert!(agent.pending_withdrawal.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_uses_only_the_exact_retained_head_when_the_operator_is_unreachable() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let account = wallets()[0].public_key();
        let current = genesis_cache();
        let stale = AccountCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance: 99,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        let current_root = current.root();
        let current_opening = current.opening(&account).unwrap();
        let stale_root = stale.root();
        let stale_opening = stale.opening(&account).unwrap();
        assert_ne!(current_root, stale_root);

        let mut agent = Agent::new(0).unwrap();
        agent
            .store
            .retain_recovery_opening(&current_root, &current_opening)
            .unwrap();
        agent
            .store
            .retain_recovery_opening(&stale_root, &stale_opening)
            .unwrap();

        // The certified head is the genesis root, so the wallet signs over its
        // exactly matching retained opening without any operator read.
        let outcome = agent
            .withdraw(
                &context,
                &mut chain,
                SocketAddr::from(([127, 0, 0, 1], 2)),
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, error } = outcome else {
            panic!("unreachable operator unexpectedly applied withdrawal");
        };
        assert_eq!(
            request.body().action(),
            &WithdrawalAction::Amount(NonZeroU64::new(7).unwrap())
        );
        assert_eq!(request.body().state_root(), &current_root.digest);
        assert!(format!("{error:#}").contains("apply operator withdrawal"));
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));

        // A wallet holding only a mismatched retained head must fetch one from
        // the operator or the slice holders, and refuses to sign when neither
        // answers.
        let mut dead_holders = client_with_holders(&context, &control, UNREACHABLE);
        let mut wrong_only = Agent::new(0).unwrap();
        wrong_only
            .store
            .retain_recovery_opening(&stale_root, &stale_opening)
            .unwrap();
        let error = wrong_only
            .withdraw(
                &context,
                &mut dead_holders,
                SocketAddr::from(([127, 0, 0, 1], 4)),
                WithdrawalAction::Close,
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("read withdrawal opening"));
        assert!(wrong_only.pending_withdrawal.is_none());
    });
}

#[test]
fn forged_head_operator_is_rejected_before_staging() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut chain = dead_client(&context);
        let impostor = Wallet::from_seed("impostor", 1_001);
        let payment_context = PaymentContext::new(
            Sha256::hash(&[b"forged-head-operator"]),
            7,
            impostor.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        payment_context,
                        AccountState {
                            balance: 100,
                            cumulative_debit: 50_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("unexpected operator"));
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 0);
        assert!(recovered.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

#[derive(Clone, Copy, Debug)]
enum PaymentHeadGateCase {
    MismatchedStateRoot,
    WrongAccount,
    InactivePayer,
    ZeroBalance,
    InvalidProof,
    HardFaulted,
}

impl PaymentHeadGateCase {
    /// The hard-faulted case permanently faults the shared chain, so it runs
    /// last.
    const ALL: [Self; 6] = [
        Self::MismatchedStateRoot,
        Self::WrongAccount,
        Self::InactivePayer,
        Self::ZeroBalance,
        Self::InvalidProof,
        Self::HardFaulted,
    ];

    const fn actor(self) -> &'static str {
        match self {
            Self::MismatchedStateRoot => "mismatched_state_root",
            Self::WrongAccount => "wrong_account",
            Self::InactivePayer => "inactive_payer",
            Self::ZeroBalance => "zero_balance",
            Self::InvalidProof => "invalid_proof",
            Self::HardFaulted => "hard_faulted",
        }
    }

    const fn expected_error(self) -> &'static str {
        match self {
            Self::MismatchedStateRoot => "payer opening is not the exact settlement head",
            Self::WrongAccount => "payer opening belongs to another account",
            Self::InactivePayer | Self::ZeroBalance => "payer opening is not live",
            Self::InvalidProof => "verify payer state opening",
            Self::HardFaulted => "settlement is permanently hard-faulted",
        }
    }

    /// Corrupts the served head. The settlement side is a certified read now,
    /// so every corruption lives in the operator's response.
    fn corrupt(self, head: &mut operator_rpc::PaymentHeadResponse) {
        match self {
            Self::MismatchedStateRoot => {
                // A verifiable opening over a root that is not the certified
                // settlement head.
                let account = wallets()[0].public_key();
                let forked = AccountCache::new::<Sha256>(vec![StateLeaf {
                    account: account.clone(),
                    state: AccountState {
                        balance: 100,
                        active: true,
                        ..AccountState::default()
                    },
                }])
                .unwrap();
                head.root = forked.root();
                head.opening = forked.opening(&account).unwrap();
            }
            Self::WrongAccount => {
                let account = wallets()[2].public_key();
                let cache = genesis_cache();
                head.opening = cache.opening(&account).unwrap();
            }
            Self::InactivePayer => head.opening.leaf.state.active = false,
            Self::ZeroBalance => head.opening.leaf.state.balance = 0,
            Self::InvalidProof => {
                head.opening.proof.proof.leaf_count = 2;
                head.opening
                    .proof
                    .proof
                    .siblings
                    .push(Sha256::hash(&[b"invalid-payer-opening"]));
            }
            Self::HardFaulted => {}
        }
    }
}

#[test]
fn adversarial_payment_heads_are_rejected_before_send_or_persistence() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        for (case_index, case) in PaymentHeadGateCase::ALL.into_iter().enumerate() {
            if matches!(case, PaymentHeadGateCase::HardFaulted) {
                // Fault the deployment for real: a registered epoch expires
                // unadmitted past its inclusive deadline.
                let registered = registered_context(&control).await;
                let height = control.advance(0).await;
                let deadline = height + 12;
                control.advance(deadline - height + 1).await;
                assert!(status(&control).await.hard_faulted);
                let _ = registered;
            }
            let database = TempDatabase::new();
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"adversarial-payment-head"]),
                7,
                operator_key(),
            );
            let mut head = payment_head_response(
                payment_context,
                AccountState {
                    balance: 100,
                    ..AccountState::default()
                },
            );
            case.corrupt(&mut head);
            let rejected_root = head.root;
            let base_port = u16::try_from(case_index).unwrap();

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 1)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let server = context.child(case.actor()).spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::PaymentHead(request) = request else {
                        panic!("expected one payment head request");
                    };
                    assert_eq!(request.account, wallets()[0].public_key());
                    rpc::Response::Success {
                        body: head.encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(case.expected_error()),
                "{case:?} returned an unexpected error: {error}"
            );
            drop(agent);
            server.await.unwrap();

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 0, "{case:?}");
            assert!(recovered.pending_payment.is_none(), "{case:?}");
            assert_eq!(recovered.receipt_count(), 0, "{case:?}");
            assert!(
                recovered
                    .store
                    .recovery_opening(&rejected_root)
                    .unwrap()
                    .is_none(),
                "{case:?} retained an unauthenticated payer opening"
            );
        }
    });
}

#[test]
fn unregistered_valid_payment_context_does_not_commit() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;

        // Epoch 0 is registered with a different boundary, so its certified
        // anchor can never match the operator's live context: the acceptance
        // below is real but unconfirmable.
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let deposits = commonware_clearing::bajillion::boundary::DepositRecord::new(
            wallets()[1].public_key(),
            1,
        )
        .unwrap();
        let deposits = DepositBatch::new(vec![deposits]).unwrap();
        let deposits_root = deposits.root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        applied(
            &control,
            &SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                deployment: deployment(),
                event: crate::protocol::DepositEvent {
                    id: Sha256::hash(&[b"other-anchor-deposit"]),
                    account: wallets()[1].public_key(),
                    amount: 1,
                },
            }),
        )
        .await;
        let signature =
            protocol.sign_chain_registration(0, 400, &deposits_root, &deposits_root, &withdrawals);
        applied(
            &control,
            &SettlementTx::RegisterEpoch(RegisterEpochRequest {
                deployment: deployment(),
                epoch: 0,
                predecessor_liability: 400,
                deposits_root,
                staged_root: deposits_root,
                withdrawals,
                openings: Vec::new(),
                signature,
            }),
        )
        .await;

        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            let mut first_send = None;

            // The retry resubmits the exact staged bytes with no second head read: the
            // real operator replays the committed batch for them.
            for expected in [
                operator_rpc::METHOD_PAYMENT_HEAD,
                operator_rpc::METHOD_ACCEPT_SEND,
                operator_rpc::METHOD_ACCEPT_SEND,
            ] {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, expected);
                    let request = operator_rpc::decode_request(request).unwrap();
                    if let operator_rpc::OperatorRequest::AcceptSend(request) = &request {
                        if let Some(first) = &first_send {
                            assert_eq!(&request.authorization, first);
                        } else {
                            first_send = Some(request.authorization.clone());
                        }
                    }
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
        });

        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("confirm payment registration"));
        assert!(error.contains("another anchor is registered"));
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        let pending = agent.pending_payment.as_ref().unwrap();
        assert!(
            agent
                .store
                .recovery_opening(&pending.recovery_root)
                .unwrap()
                .is_some()
        );

        // The exact retry replays the committed batch, and the certified
        // anchor still refuses it: an acceptance under a context settlement
        // never registered is permanently unrecordable.
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("confirm payment registration"));
        assert!(error.contains("another anchor is registered"));
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        assert!(agent.pending_payment.is_some());
        operator_server.await.unwrap();
    });
}

#[test]
fn response_loss_restart_retries_byte_identical_pending_send() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = registered_context(&control).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server_context = payment_context.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            let payment_context = server_context;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            cumulative_debit: 50_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;

            let accepted;
            let first_authorization;
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let operator_rpc::OperatorRequest::AcceptSend(request) =
                    operator_rpc::decode_request(request).unwrap()
                else {
                    panic!("expected the initially staged send");
                };
                assert_eq!(request.authorization.body().cumulative_debit(), 7);
                accepted =
                    issue_acceptance(&operator, &[], &request.authorization, &request.entries);
                first_authorization = request.authorization;
            }

            // The restarted retry resubmits the exact staged bytes with no head read.
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("restart retry unexpectedly skipped its resubmission");
                };
                assert_eq!(request.authorization.encode(), first_authorization.encode());
                rpc::Response::Success {
                    body: accept_response(operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 1,
                        total: 7,
                        acceptance: accepted,
                    }),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        assert!(agent.pending_payment.is_some());
        drop(agent);

        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_payment.is_some());
        let payment = accepted(
            recovered
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.entries[0].cumulative, 7);
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 1);
        assert!(recovered.pending_payment.is_none());
        drop(recovered);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_payment.is_none());
        assert_eq!(recovered.receipt_count(), 1);
        operator_server.await.unwrap();
    });
}

#[test]
fn successful_receipt_commit_survives_restart_and_advances_next_debit() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = registered_context(&control).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server_context = payment_context.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            let payment_context = server_context;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: payment_head_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            cumulative_debit: 10_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond_acceptance(&mut listener, &operator, &payment_context, 7, Vec::new()).await;

            // The cached signing state is durable, so the restarted wallet signs its
            // next send from local SQL alone: no head read precedes it.
            respond_acceptance(
                &mut listener,
                &operator,
                &payment_context,
                10,
                bob_edge(7, 1),
            )
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent
            .pay(&context, &mut chain, operator_address, &[(1, 7)])
            .await
            .unwrap();
        drop(agent);

        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 1);
        recovered
            .pay(&context, &mut chain, operator_address, &[(1, 3)])
            .await
            .unwrap();
        drop(recovered);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 10);
        assert_eq!(recovered.receipt_count(), 2);
        operator_server.await.unwrap();
    });
}

/// The acknowledgement is a courtesy to the operator's bookkeeping: a claim
/// completes on the certified release, so a lost acknowledgement response
/// holds nothing open and a restarted wallet has nothing left to retry.
#[test]
fn withdrawal_claim_completes_when_the_acknowledgement_is_lost() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let result = operator.complete_close(25).unwrap();
        finalize(&control, &result).await;

        let account = wallets()[0].public_key();
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let evidence = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };
        let release = crate::chain::state::WithdrawalResponse {
            amount: evidence.claim.output().amount(),
            destination: evidence.claim.output().destination().clone(),
        };

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = evidence.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::WithdrawalEvidence(request) = request else {
                    panic!("expected withdrawal evidence request");
                };
                assert_eq!(request.account, operator_evidence.account);
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;

            // The acknowledgement is applied, but its response is lost.
            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let request =
                operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap();
            let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                panic!("expected withdrawal acknowledgement");
            };
            assert_eq!(request.as_ref(), &operator_evidence);
            assert!(matches!(
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request),
                rpc::Response::Success { .. }
            ));
            drop(sink);
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, operator_address)
                .await
                .unwrap(),
            release
        );
        assert!(agent.pending_withdrawal_claim.is_none());
        assert!(
            agent
                .store
                .withdrawal_claim_completed(evidence.batch_id, evidence.claim.position())
                .unwrap()
        );
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_withdrawal_claim.is_none());
        operator_server.await.unwrap();
    });
}

/// The external-payout twin of the lost acknowledgement: the certified release
/// completes the claim.
#[test]
fn external_payout_claim_completes_when_the_acknowledgement_is_lost() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        let result = operator.complete_close(26).unwrap();
        finalize(&control, &result).await;

        let identity = wallets().len();
        let account = external_identity().key;
        let evidence = operator.external_payout_evidence(&account).unwrap();
        let evidence = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: evidence.batch_id,
            claim: evidence.claim,
        };
        let payout = crate::chain::state::ExternalPayoutResponse {
            receiver: account.clone(),
            amount: 100,
        };

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = evidence.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::ExternalPayoutEvidence(request) = request else {
                    panic!("expected external-payout evidence request");
                };
                assert_eq!(request.account, account);
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;

            // The acknowledgement is applied, but its response is lost.
            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let request =
                operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap();
            let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request else {
                panic!("expected external-payout acknowledgement");
            };
            assert_eq!(request.as_ref(), &operator_evidence);
            assert!(matches!(
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request),
                rpc::Response::Success { .. }
            ));
            drop(sink);
        });

        let mut agent = Agent::open(database.path(), identity).unwrap();
        assert_eq!(
            agent
                .claim_external_payout(&context, &mut chain, operator_address)
                .await
                .unwrap(),
            payout
        );
        assert!(agent.pending_payout_claim.is_none());
        drop(agent);

        let recovered = Agent::open(database.path(), identity).unwrap();
        assert!(recovered.pending_payout_claim.is_none());
        operator_server.await.unwrap();
    });
}

/// The exact cross-batch replay attack: after claim #1 completes, a Byzantine
/// operator re-serves batch #1's evidence for the wallet's new intent. The
/// old batch's claim roots still verify it, so only the durable completed set
/// can refuse it. The wallet must keep the intent open and complete it only
/// on genuine batch #2 evidence, with the completed set surviving a restart.
#[test]
fn withdrawal_claim_refuses_replayed_evidence_across_batches() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let account = wallets()[0].public_key();

        // Two finalized batches, each carrying one withdrawal for the wallet.
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let first = operator.complete_close(41).unwrap();
        finalize(&control, &first).await;
        let stale = operator.withdrawal_evidence(&account).unwrap();
        let stale = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: stale.batch_id,
            account: stale.account,
            claim: stale.claim,
        };
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(20).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let second = operator.complete_close(42).unwrap();
        finalize(&control, &second).await;
        assert_ne!(first.finalized.batch_id, second.finalized.batch_id);

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 11)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let served_stale = stale.clone();
        let served_account = account.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // Claim #1: evidence, then the acknowledgement that retires it.
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: served_stale.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected the first withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;

            // The Byzantine replay: batch #1's spent evidence for intent #2.
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: served_stale.encode(),
                }
            })
            .await;

            // The honest retry: the acknowledged store serves batch #2.
            let fresh = operator.withdrawal_evidence(&served_account).unwrap();
            let fresh = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: fresh.batch_id,
                account: fresh.account,
                claim: fresh.claim,
            };
            assert_ne!(fresh.batch_id, served_stale.batch_id);
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: fresh.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected the second withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
        });

        // Claim #1 completes and durably consumes its (batch, position).
        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let release = agent
            .claim_withdrawal(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(release.amount, 25);
        assert!(agent.pending_withdrawal_claim.is_none());
        assert!(
            agent
                .store
                .withdrawal_claim_completed(stale.batch_id, stale.claim.position())
                .unwrap()
        );
        drop(agent);

        // The completed set survives the restart, so the re-served batch #1
        // evidence is refused for intent #2: nothing is cached, no settlement
        // claim is submitted, and the intent stays open.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let refused = agent
            .claim_withdrawal(&context, &mut chain, operator_address)
            .await
            .unwrap_err();
        assert!(
            format!("{refused:#}").contains("already-completed withdrawal claim"),
            "unexpected refusal: {refused:#}"
        );
        let pending = agent.pending_withdrawal_claim.clone().unwrap();
        assert!(pending.evidence.is_none());
        assert!(pending.result.is_none());

        // Genuine batch #2 evidence completes the open intent.
        let release = agent
            .claim_withdrawal(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(release.amount, 20);
        assert!(agent.pending_withdrawal_claim.is_none());
        operator_server.await.unwrap();

        // The store-level cache guard is the same refusal one layer deeper.
        let refused = agent.store.cache_withdrawal_claim(&stale).unwrap_err();
        assert!(format!("{refused:#}").contains("already-completed (batch, position)"));
    });
}

/// The external-payout twin of the cross-batch replay attack.
#[test]
fn external_payout_claim_refuses_replayed_evidence_across_batches() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let identity = wallets().len();
        let account = external_identity().key;

        // Two finalized batches, each paying the external receiver once.
        register(&control, &mut operator).await;
        operator.pay(0, operator.wallet_count(), 40).unwrap();
        let first = operator.complete_close(43).unwrap();
        finalize(&control, &first).await;
        let stale = operator.external_payout_evidence(&account).unwrap();
        let stale = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: stale.batch_id,
            claim: stale.claim,
        };
        register(&control, &mut operator).await;
        operator.pay(0, operator.wallet_count(), 30).unwrap();
        let second = operator.complete_close(44).unwrap();
        finalize(&control, &second).await;
        assert_ne!(first.finalized.batch_id, second.finalized.batch_id);

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 12)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let served_stale = stale.clone();
        let served_account = account.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // Claim #1: evidence, then the acknowledgement that retires it.
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: served_stale.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("expected the first payout acknowledgement");
                };
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
            })
            .await;

            // The Byzantine replay: batch #1's spent evidence for intent #2.
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: served_stale.encode(),
                }
            })
            .await;

            // The honest retry: the acknowledged store serves batch #2.
            let fresh = operator.external_payout_evidence(&served_account).unwrap();
            let fresh = operator_rpc::ExternalPayoutEvidenceResponse {
                batch_id: fresh.batch_id,
                claim: fresh.claim,
            };
            assert_ne!(fresh.batch_id, served_stale.batch_id);
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: fresh.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("expected the second payout acknowledgement");
                };
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
            })
            .await;
        });

        // Claim #1 completes and durably consumes its (batch, position).
        let mut agent = Agent::open(database.path(), identity).unwrap();
        let payout = agent
            .claim_external_payout(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(payout.amount, 40);
        assert!(agent.pending_payout_claim.is_none());
        assert!(
            agent
                .store
                .payout_claim_completed(stale.batch_id, stale.claim.position())
                .unwrap()
        );
        drop(agent);

        // The completed set survives the restart, so the re-served batch #1
        // evidence is refused for the new intent, which stays open.
        let mut agent = Agent::open(database.path(), identity).unwrap();
        let refused = agent
            .claim_external_payout(&context, &mut chain, operator_address)
            .await
            .unwrap_err();
        assert!(
            format!("{refused:#}").contains("already-completed external-payout claim"),
            "unexpected refusal: {refused:#}"
        );
        let pending = agent.pending_payout_claim.clone().unwrap();
        assert!(pending.evidence.is_none());
        assert!(pending.result.is_none());

        // Genuine batch #2 evidence completes the open intent.
        let payout = agent
            .claim_external_payout(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(payout.amount, 30);
        assert!(agent.pending_payout_claim.is_none());
        operator_server.await.unwrap();

        // The store-level cache guard is the same refusal one layer deeper.
        let refused = agent.store.cache_payout_claim(&stale).unwrap_err();
        assert!(format!("{refused:#}").contains("already-completed (batch, position)"));
    });
}

#[test]
fn foreign_withdrawal_evidence_is_never_cached() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(1, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let result = operator.complete_close(27).unwrap();
        finalize(&control, &result).await;

        // Bob's certified claim pays destination "Bob". A hostile operator relabels the
        // evidence with Alice's account and serves it to Alice.
        let victim = wallets()[0].public_key();
        let evidence = operator
            .withdrawal_evidence(&wallets()[1].public_key())
            .unwrap();
        let forged = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: victim,
            claim: evidence.claim,
        };

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: forged.encode(),
                }
            })
            .await;
        });

        // The genuine claim verifies against the certified batch's own root and the
        // forged account label passes its check, so only the destination binding stands
        // between Alice and caching Bob's claim as her own.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let error = agent
            .claim_withdrawal(&context, &mut chain, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("another destination"));
        assert!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        drop(agent);

        // Nothing was cached, so a restarted wallet fetches fresh evidence.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(
            recovered
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        operator_server.await.unwrap();
    });
}

#[test]
fn staged_deposit_survives_restart_and_retries_the_same_id() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;

        // The wallet stages durably, then dies before the chain classifies
        // the submission. The unreachable chain stands in for that crash
        // window.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let mut dead = dead_client(&context);
        let error = agent.deposit(&context, &mut dead, 7).await.unwrap_err();
        assert!(format!("{error:#}").contains("record settlement deposit"));
        let event = agent.pending_deposit.clone().unwrap();
        drop(agent);

        // The restarted wallet restores the exact staged event, so the retry replays
        // the recorded id even though its volatile nonce differs.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.pending_deposit.as_ref(), Some(&event));
        recovered.deposit_nonce = 41;
        let applied = recovered.deposit(&context, &mut chain, 7).await.unwrap();
        assert_eq!(applied, event);
        assert!(recovered.pending_deposit.is_none());
        assert_eq!(recovered.deposit_nonce, 42);
        drop(recovered);

        let reopened = Agent::open(database.path(), 0).unwrap();
        assert!(reopened.pending_deposit.is_none());
        assert_eq!(status(&control).await.custody, 407);
    });
}

#[test]
fn doomed_deposit_keeps_the_staged_event_and_surfaces_advice() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;

        // The deposit amount exceeds the operator storage domain, so the
        // chain rejects it, with no effect and no custody taken.
        let amount = crate::protocol::SQLITE_U64_MAX;

        // The first attempt cannot be classified: the chain is unreachable, so
        // the staged event must survive for an exact retry.
        let mut dead = dead_client(&context);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .deposit(&context, &mut dead, amount)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("record settlement deposit"));
        assert!(agent.pending_deposit.is_some());
        let staged = agent.pending_deposit.clone().unwrap();

        // The retry replays the exact staged event. The rejection is
        // effect-free and therefore indistinguishable from not-yet-included,
        // so the staged event survives for an exact retry and the advisory
        // dry-run answer is surfaced as the diagnosis.
        let error = agent
            .deposit(&context, &mut chain, amount)
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("record settlement deposit"), "{message}");
        assert!(message.contains("Doomed(Domain)"), "{message}");
        assert!(agent.pending_deposit.is_some());
        assert_eq!(
            control
                .submit(SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                    deployment: deployment(),
                    event: staged.clone(),
                }))
                .await
                .1,
            Advice::Doomed(Reject::Domain)
        );
        assert_eq!(
            control.record(deposit_key(&deployment(), &staged.id)).await,
            None
        );
        assert_eq!(status(&control).await.custody, 400);
        drop(agent);

        // The staged event is durable, so a restart still retries the exact
        // bytes: no custody can ever move without the wallet holding the
        // matching staged record.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.pending_deposit, Some(staged));
    });
}

#[test]
fn unfinalized_batch_evidence_is_not_cached_and_completes_after_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let result = operator.complete_close(28).unwrap();
        finalize(&control, &result).await;

        let account = wallets()[0].public_key();
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let honest = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };

        // Well formed and destination bound, but naming a batch the chain does
        // not know: an unknown batch is a certified absence, not finalized, so
        // nothing may enter the cache and the claim retries later.
        let poisoned = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: BatchId::new(Sha256::hash(&[b"mislabeled-withdrawal-batch"])),
            account: honest.account.clone(),
            claim: honest.claim.clone(),
        };
        let release = crate::chain::state::WithdrawalResponse {
            amount: honest.claim.output().amount(),
            destination: honest.claim.output().destination().clone(),
        };

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = honest.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: poisoned.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let error = agent
            .claim_withdrawal(&context, &mut chain, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("has not finalized"));
        assert!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        drop(agent);

        // Nothing entered the cache, and the next fetch verifies against the
        // certified finalized batch and completes the claim.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            recovered
                .claim_withdrawal(&context, &mut chain, operator_address)
                .await
                .unwrap(),
            release
        );
        assert!(recovered.pending_withdrawal_claim.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn cached_evidence_claims_after_the_operator_vanishes() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let result = operator.complete_close(31).unwrap();
        finalize(&control, &result).await;

        let account = wallets()[0].public_key();
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let honest = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };
        let release = crate::chain::state::WithdrawalResponse {
            amount: honest.claim.output().amount(),
            destination: honest.claim.output().destination().clone(),
        };

        // The operator serves the evidence once and then vanishes for good.
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = honest.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;
        });

        // The reserve releases from the self-verified copy against the
        // certified batch, and the vanished operator's missing acknowledgement
        // holds nothing open.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, operator_address)
                .await
                .unwrap(),
            release
        );
        assert!(agent.pending_withdrawal_claim.is_none());
        operator_server.await.unwrap();
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_withdrawal_claim.is_none());
        assert!(
            recovered
                .store
                .withdrawal_claim_completed(honest.batch_id, honest.claim.position())
                .unwrap()
        );
    });
}

#[test]
fn unfinalized_batch_payout_evidence_is_not_cached_and_completes_after_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        let result = operator.complete_close(32).unwrap();
        finalize(&control, &result).await;

        let identity = wallets().len();
        let account = external_identity().key;
        let evidence = operator.external_payout_evidence(&account).unwrap();
        let honest = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: evidence.batch_id,
            claim: evidence.claim,
        };

        // Receiver bound, but naming a batch the chain does not know: an unknown
        // batch is a certified absence, not finalized, so nothing may enter the cache.
        let poisoned = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: BatchId::new(Sha256::hash(&[b"mislabeled-payout-batch"])),
            claim: honest.claim.clone(),
        };
        let payout = crate::chain::state::ExternalPayoutResponse {
            receiver: account.clone(),
            amount: 100,
        };

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = honest.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: poisoned.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("expected external-payout acknowledgement");
                };
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), identity).unwrap();
        let error = agent
            .claim_external_payout(&context, &mut chain, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("has not finalized"));
        assert!(
            agent
                .pending_payout_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        drop(agent);

        // Nothing entered the cache, and the next fetch verifies against the
        // certified finalized batch and completes the claim.
        let mut recovered = Agent::open(database.path(), identity).unwrap();
        assert_eq!(
            recovered
                .claim_external_payout(&context, &mut chain, operator_address)
                .await
                .unwrap(),
            payout
        );
        assert!(recovered.pending_payout_claim.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn released_evidence_is_immutable_until_acknowledged() {
    deterministic::Runner::default().start(|_context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        operator.complete_close(33).unwrap();

        let account = wallets()[0].public_key();
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let honest = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };
        let release = crate::chain::state::WithdrawalResponse {
            amount: honest.claim.output().amount(),
            destination: honest.claim.output().destination().clone(),
        };

        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent.store.open_withdrawal_claim().unwrap();
        agent.store.cache_withdrawal_claim(&honest).unwrap();
        agent
            .store
            .record_withdrawal_result(&honest, &release)
            .unwrap();

        // A recorded release pins its evidence until the acknowledgement completes,
        // so an overwrite attempt fails instead of replacing it.
        let replacement = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: BatchId::new(Sha256::hash(&[b"replacement-batch"])),
            account: honest.account.clone(),
            claim: honest.claim.clone(),
        };
        let error = agent
            .store
            .cache_withdrawal_claim(&replacement)
            .unwrap_err();
        assert!(format!("{error:#}").contains("immutable"));
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        let held = recovered.pending_withdrawal_claim.unwrap();
        assert_eq!(held.evidence, Some(honest));
        assert_eq!(held.result, Some(release));
    });
}

#[test]
fn endpoint_resolved_payment_recovers_after_hard_fault_frozen_at_its_head() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let account = wallets()[0].public_key();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The operator commits the batch but its response is lost.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let recorded = accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator, recorded)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, &mut chain, address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let (mut listener, mut operator, _recorded) = staging.await.unwrap();

        // The committed send finalizes certifiably at the head H, and epoch 1
        // registers so its later expiry freezes the deployment at H.
        let result = operator.complete_close(34).unwrap();
        finalize(&control, &result).await;
        let frozen_root = result.finalized.successor_root;
        register(&control, &mut operator).await;

        // The retry earns a corrective naming the committed endpoint (a lossy
        // front: the live operator would replay the committed batch),
        // resolution proves the commitment at H and retains H's opening, and
        // the operator then serves no batch: committed with receipts unheld.
        let stale = operator
            .payment_head(&wallets()[0].public_key())
            .unwrap()
            .context;
        let resolution = context.child("resolution").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
                rpc::Response::Success {
                    body: stale_response(&stale, 7),
                }
            })
            .await;
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptedBatch(_)
                ));
                rpc::Response::Success {
                    body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                }
            })
            .await;
        });
        let outcome = agent
            .pay(&context, &mut chain, address, &[(1, 7)])
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
        ));
        drop(agent);
        resolution.await.unwrap();

        // The operator vanishes and epoch 1 expires unadmitted, hard-faulting
        // the deployment frozen at H.
        let height = control.advance(0).await;
        let mut faulted = status(&control).await;
        let mut advanced = height;
        while !faulted.hard_faulted {
            advanced = control.advance(1).await;
            assert!(advanced < height + 30, "the deployment never faulted");
            faulted = status(&control).await;
        }
        assert_eq!(faulted.state_root, frozen_root);

        // Recovery finds the opening retained at resolution, with no other head read.
        let recovered = Agent::open(database.path(), 0).unwrap();
        let release = recovered
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap();
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, 93);
        assert_eq!(release.residual, 93);
        assert_eq!(release.withdrawal, None);
        let _ = advanced;
    });
}

#[test]
fn false_epoch_withdrawal_ack_cannot_strand_the_claim() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let account = wallets()[0].public_key();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // A Byzantine operator acknowledges the exact request but lies about
        // the epoch. The digest binds the request, the epoch binds nothing.
        let applying = context.child("applying").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            respond_rpc(&mut listener, |request| {
                let operator_rpc::OperatorRequest::ApplyWithdrawal(request) =
                    operator_rpc::decode_request(request).unwrap()
                else {
                    panic!("expected the signed withdrawal");
                };
                let digest = operator_rpc::withdrawal_digest(&request.request);
                operator.apply_withdrawal(request.request).unwrap();
                rpc::Response::Success {
                    body: operator_rpc::WithdrawalAck { epoch: 999, digest }.encode(),
                }
            })
            .await;
            (listener, operator)
        });

        let mut agent = Agent::new(0).unwrap();
        let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let outcome = agent
            .withdraw(&context, &mut chain, address, action)
            .await
            .unwrap();

        // The lie lands only in the display value. The durable intent carries no
        // epoch, so nothing pins the claim to the false batch.
        let WithdrawalOutcome::Applied { epoch, .. } = outcome else {
            panic!("acknowledged withdrawal was not applied");
        };
        assert_eq!(epoch, 999);
        let (mut listener, mut operator) = applying.await.unwrap();

        // The true reserve finalizes in the real certified epoch-0 batch.
        register(&control, &mut operator).await;
        let result = operator.complete_close(35).unwrap();
        finalize(&control, &result).await;
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let expected = crate::chain::state::WithdrawalResponse {
            amount: evidence.claim.output().amount(),
            destination: evidence.claim.output().destination().clone(),
        };
        let claiming = context.child("claiming").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
        });

        let release = agent
            .claim_withdrawal(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(release, expected);
        assert_eq!(release.amount, 7);
        assert!(agent.pending_withdrawal_claim.is_none());
        claiming.await.unwrap();
    });
}

#[test]
fn withdrawal_is_refused_while_a_prior_claim_is_unfinished() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let account = wallets()[0].public_key();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The first withdrawal is applied for real.
        let applying = context.child("applying").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        let first = agent
            .withdraw(
                &context,
                &mut chain,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        assert!(matches!(first, WithdrawalOutcome::Applied { .. }));
        let (mut listener, mut operator) = applying.await.unwrap();

        // Its close is admitted but not finalized: the slice holders serve the
        // claim inside the window and the wallet caches it, but settlement
        // cannot release it yet, so the claim stays unfinished with its
        // evidence pinned. The operator is not asked.
        register(&control, &mut operator).await;
        let first_close = operator.complete_close(36).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&first_close)),
        )
        .await;
        let waiting = agent
            .claim_withdrawal(&context, &mut chain, address)
            .await
            .unwrap_err();
        assert!(format!("{waiting:#}").contains("has not finalized"));
        let held = agent.pending_withdrawal_claim.clone().unwrap();
        assert!(held.evidence.is_some());
        assert!(held.result.is_none());

        // A second withdrawal is refused cleanly while the claim is unfinished,
        // and the pinned claim state survives untouched.
        let refused = agent
            .withdraw(
                &context,
                &mut chain,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
            )
            .await
            .unwrap_err();
        assert!(format!("{refused:#}").contains("pending withdrawal claim must complete"));
        assert!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_some())
        );

        // Finalization completes the first claim from the cached copy and
        // unblocks the second withdrawal, and both reserves release against
        // their own certified batches.
        finalize(&control, &first_close).await;
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let first_expected = crate::chain::state::WithdrawalResponse {
            amount: evidence.claim.output().amount(),
            destination: evidence.claim.output().destination().clone(),
        };
        let completing = context.child("completing").spawn(move |_| async move {
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected the first withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let first_release = agent
            .claim_withdrawal(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(first_release, first_expected);
        assert_eq!(first_release.amount, 7);
        assert!(agent.pending_withdrawal_claim.is_none());
        let second = agent
            .withdraw(
                &context,
                &mut chain,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
            )
            .await
            .unwrap();
        assert!(matches!(second, WithdrawalOutcome::Applied { .. }));
        let (mut listener, mut operator) = completing.await.unwrap();

        // The second close finalizes before the wallet claims, so the holders
        // have released its dealing and the operator's reconstruction serves.
        register(&control, &mut operator).await;
        let second_close = operator.complete_close(37).unwrap();
        finalize(&control, &second_close).await;
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let second_expected = crate::chain::state::WithdrawalResponse {
            amount: evidence.claim.output().amount(),
            destination: evidence.claim.output().destination().clone(),
        };
        let finishing = context.child("finishing").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected the second withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
        });
        let second_release = agent
            .claim_withdrawal(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(second_release, second_expected);
        assert_eq!(second_release.amount, 5);
        assert!(agent.pending_withdrawal_claim.is_none());
        finishing.await.unwrap();
    });
}

#[test]
fn balance_poll_retains_the_head_for_hard_fault_recovery() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let account = wallets()[0].public_key();

        // The registered epoch later expires unadmitted, freezing the
        // deployment at the genesis head the balance poll retained.
        let payment_context = registered_context(&control).await;
        let head = payment_head_response(
            payment_context,
            AccountState {
                balance: 100,
                ..AccountState::default()
            },
        );
        let frozen_root = head.root;

        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context.child("server").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                rpc::Response::Success {
                    body: head.encode(),
                }
            })
            .await;
        });

        // Balance polling alone verifies and retains the current head opening.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            agent.balance(&context, &mut chain, address).await.unwrap(),
            100
        );
        drop(agent);
        server.await.unwrap();

        // The operator vanishes and the registration expires into a permanent
        // fault frozen at the retained head.
        let height = control.advance(0).await;
        let mut faulted = status(&control).await;
        while !faulted.hard_faulted {
            let advanced = control.advance(1).await;
            assert!(advanced < height + 30, "the deployment never faulted");
            faulted = status(&control).await;
        }
        assert_eq!(faulted.state_root, frozen_root);

        let recovered = Agent::open(database.path(), 0).unwrap();
        let release = recovered
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap();
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, 100);
    });
}

/// Registers the omitting boundary on the chain, builds the deterministic
/// omitting close at the chain-assigned deadlines (the admitted close credits
/// a deposit to a bystander and omits Bob, while Bob holds an operator-signed
/// receipt crediting him), and admits it, so its inclusive challenge window
/// is open until the assigned absolute deadline.
async fn admit_omitting(control: &harness::Control) -> crate::protocol::OmittingClose {
    let (deposit, deposits) = crate::protocol::omitting_boundary().unwrap();
    applied(
        control,
        &SettlementTx::Deposit(crate::chain::tx::DepositRequest {
            deployment: deployment(),
            event: deposit,
        }),
    )
    .await;
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let deposits_root = deposits.root::<Sha256>().unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let signature =
        protocol.sign_chain_registration(0, 400, &deposits_root, &deposits_root, &withdrawals);
    applied(
        control,
        &SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,
            staged_root: deposits_root,
            withdrawals,
            openings: Vec::new(),
            signature,
        }),
    )
    .await;
    let record = registration_record(control).await;
    let fixture = crate::protocol::omitting_close(
        &mut TestRng::new(7),
        record.admission_deadline,
        record.challenge_deadline,
    )
    .unwrap();
    applied(
        control,
        &SettlementTx::Admit(AdmitRequest::from(&fixture.result)),
    )
    .await;
    fixture
}

/// Drives the admitted omitting close past its challenge window to certified
/// finalization.
async fn finalize_omitting(control: &harness::Control, fixture: &crate::protocol::OmittingClose) {
    let deadline = fixture.result.epoch_context.challenge_deadline();
    let height = control.advance(0).await;
    if height <= deadline {
        control.advance(deadline - height + 1).await;
    }
    let status = status(control).await;
    assert!(status.last_finalized == Some(0) && !status.hard_faulted);
}

/// The batch identity the chain anchors an admitted close on.
fn admitted_batch(fixture: &crate::protocol::OmittingClose) -> BatchId<Digest> {
    fixture.result.header.batch_id::<Sha256>()
}

fn incoming_response(pairs: &[(Receipt, u64)]) -> operator_rpc::IncomingPaymentsResponse {
    operator_rpc::IncomingPaymentsResponse {
        next_cursor: pairs.last().map_or(0, |(_, cursor)| *cursor),
        pairs: pairs
            .iter()
            .map(|(receipt, cursor)| operator_rpc::IncomingPair {
                sequence: *cursor,
                receipt: receipt.clone(),
            })
            .collect(),
    }
}

/// A held receipt crediting Bob from `payer` under the omitting close's epoch context.
fn held_from(fixture: &crate::protocol::OmittingClose, payer: &Wallet) -> Receipt {
    issued_receipt(
        &fixture.result.payment_context,
        payer,
        &wallets()[1].public_key(),
        5,
    )
}

/// A second paying edge whose payer key sorts after Alice's, so reconciliation assesses
/// the fixture's Alice edge first.
fn later_payer() -> Wallet {
    let alice = wallets()[0].public_key();
    (2_000..2_100)
        .map(|seed| Wallet::from_seed("later-payer", seed))
        .find(|wallet| wallet.public_key() > alice)
        .expect("a seeded key sorts after Alice")
}

/// (c) THE POINT: a receiver holding a verified receipt convicts a close that omits its
/// credit, end to end through a real challenge transaction whose proven verdict is read
/// back certified, and the close is invalidated. With the slice holders dead, the
/// operator's own served lookup is what convicts it.
#[test]
fn omitted_credit_is_convicted_by_the_held_receipt() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, UNREACHABLE);
        let fixture = admit_omitting(&control).await;
        let bob_receipt = fixture.held_receipt.clone();
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let bob_lookup = fixture.held_lookup.clone();
        assert!(!status(&control).await.hard_faulted);

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_receipt, 1)]).encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                let operator_rpc::OperatorRequest::CommittedEntry(request) = request else {
                    panic!("expected a committed entry request");
                };
                assert_eq!(request.payer, wallets()[0].public_key());
                assert_eq!(request.recipient, wallets()[1].public_key());
                assert_eq!(request.epoch, 0);
                rpc::Response::Success {
                    body: operator_rpc::CommittedEntryResponse {
                        batch_id,
                        change_root,
                        lookup: bob_lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        let ledger = bob.incoming();
        assert_eq!(ledger.count, 1);
        assert_eq!(ledger.total, 5);

        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.convicted, [0]);

        // The proven challenge invalidated the close: the deployment is
        // certifiably hard-faulted with the conviction in its fault record,
        // and Bob durably recorded the epoch as decided so it is no longer
        // reconciled or retried.
        let after = chain.status(&context).await.unwrap();
        assert!(after.hard_faulted);
        assert!(matches!(
            control.record(fault_key(&deployment())).await,
            Some(Record::Fault(FaultRecord::Faulted(
                HardFaultReasonResponse::ProvenChallenge { batch_id: proven, .. }
            ))) if proven == batch_id
        ));
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert_eq!(bob.last_reconciled_epoch(), None);
        operator_server.await.unwrap();
    });
}

/// Item 1: a receipt whose context anchor is not the one the chain certifiably registered
/// has no close to adjudicate against, so intake refuses it. It never becomes
/// reliance-grade, and the durable cursor still advances past it so a poisoned receipt
/// cannot wedge intake.
#[test]
fn fabricated_anchor_pair_is_refused_at_intake() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;

        // A sig-valid receipt over an operator-chosen anchor with no settlement obligation.
        let bogus = PaymentContext::new(
            Sha256::hash(&[b"fabricated-unregistered-anchor"]),
            0,
            operator_key(),
        );
        let alice = &wallets()[0];
        let bob = wallets()[1].public_key();
        let payer = alice.public_key();
        let receipt = issued_receipt(&bogus, alice, &bob, 5);
        let invoice = Sha256::hash(&[receipt.ack.body().encode().as_ref()]);

        // The chain registered a different anchor for epoch 0 than the operator's forgery.
        let registered = registered_context(&control).await;
        assert_ne!(registered.anchor(), bogus.anchor());

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(receipt, 1)]).encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();

        // The forged receipt is not stored, so it never reaches the service-accounting
        // query, and the cursor advanced past it.
        assert_eq!(
            bob.incoming(),
            IncomingSummary {
                total: 0,
                count: 0,
                cursor: 1,
            }
        );
        assert_eq!(bob.paid(&payer, &invoice).unwrap(), None);
        operator_server.await.unwrap();
    });
}

/// Item 2A: one proven challenge invalidates the whole close, so a wallet holding understated
/// receipts on several payer edges convicts once and stops rather than resubmitting distinct
/// evidence under the same batch and tripping the chain's evidence-replay guard.
#[test]
fn multi_edge_understatement_convicts_once() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, UNREACHABLE);
        let fixture = admit_omitting(&control).await;
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let lookup = fixture.held_lookup.clone();
        let alice_edge = fixture.held_receipt.clone();
        let later_edge = held_from(&fixture, &later_payer());

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(alice_edge, 1), (later_edge, 2)]).encode(),
                }
            })
            .await;

            // Only the first edge is ever fetched: a second committed-entry request would
            // block here forever, so completing proves the loop stopped after one conviction.
            respond(&mut operator_listener, move |request| {
                let operator_rpc::OperatorRequest::CommittedEntry(request) = request else {
                    panic!("expected a committed entry request");
                };
                assert_eq!(request.payer, wallets()[0].public_key());
                rpc::Response::Success {
                    body: operator_rpc::CommittedEntryResponse {
                        batch_id,
                        change_root,
                        lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().count, 2);

        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.convicted, [0]);
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert!(chain.status(&context).await.unwrap().hard_faulted);
        operator_server.await.unwrap();
    });
}

/// Item 2B: a decodable tip whose batch and root match the anchor but whose lookup cannot be
/// cryptographically resolved is demoted to a soft per-epoch refusal, not an abort of the
/// reconcile pass. The epoch stays unreconciled and retries rather than shadowing others.
#[test]
fn unresolvable_lookup_is_a_soft_refusal_not_an_abort() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, UNREACHABLE);
        let fixture = admit_omitting(&control).await;
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let bob_receipt = fixture.held_receipt.clone();

        // A lookup built against another close's root: it decodes and is served under the
        // anchored batch and root, but it cannot resolve against this close's change root.
        let mut foreign = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        foreign.pay(0, 1, 5).unwrap();
        foreign.complete_close(41).unwrap();
        let foreign_lookup = foreign
            .committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0)
            .unwrap()
            .lookup;
        assert!(
            foreign_lookup
                .resolve::<Sha256>(
                    &change_root,
                    &wallets()[0].public_key(),
                    &wallets()[1].public_key(),
                )
                .is_err()
        );
        let poison_body = operator_rpc::CommittedEntryResponse {
            batch_id,
            change_root,
            lookup: foreign_lookup,
        }
        .encode();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_receipt, 1)]).encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::CommittedEntry(_)
                ));
                rpc::Response::Success { body: poison_body }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();

        // The unresolvable lookup did not abort the pass with an error, and it neither
        // convicted nor reconciled: the epoch stays unreconciled and retries, and no
        // challenge reached the chain (a proven one would have faulted it).
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert!(summary.is_empty());
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);
        assert!(!chain.status(&context).await.unwrap().hard_faulted);
        operator_server.await.unwrap();
    });
}

/// Item 2D: a certifiably finalized close that understated a held receipt past the challenge
/// window is an enforcement dead end, recorded loudly rather than silently skipped.
#[test]
fn finalized_understatement_alarms() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let fixture = admit_omitting(&control).await;
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let lookup = fixture.held_lookup.clone();
        let bob_receipt = fixture.held_receipt.clone();

        // The omitting close finalizes for real: its challenge window passes
        // unchallenged.
        finalize_omitting(&control, &fixture).await;

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_receipt, 1)]).encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::CommittedEntry(_)
                ));
                rpc::Response::Success {
                    body: operator_rpc::CommittedEntryResponse {
                        batch_id,
                        change_root,
                        lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();

        // The dead end is loud and terminal: recorded, surfaced, and never reconciled.
        assert_eq!(summary.unenforceable, [0]);
        assert!(summary.reconciled.is_empty() && summary.convicted.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert_eq!(bob.last_reconciled_epoch(), None);
        operator_server.await.unwrap();
    });
}

/// A finalized close whose committed evidence the operator withholds is an alarm, not a silent
/// retry: conviction is no longer possible and coverage cannot be verified, so the dead end is
/// surfaced once per stretch of withholding while the epoch keeps retrying, and it self-heals
/// into a terminal verdict if the evidence is eventually served.
#[test]
fn withheld_evidence_past_finalization_alarms_once() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let fixture = admit_omitting(&control).await;
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let lookup = fixture.held_lookup.clone();
        let bob_receipt = fixture.held_receipt.clone();
        finalize_omitting(&control, &fixture).await;

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_receipt, 1)]).encode(),
                }
            })
            .await;

            // Two stretches of withholding, then the real served lookup.
            for _ in 0..2 {
                respond(&mut operator_listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::CommittedEntry(_)
                    ));
                    rpc::Response::Error {
                        error: Bytes::from_static(b"withheld"),
                    }
                })
                .await;
            }
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::CommittedEntry(_)
                ));
                rpc::Response::Success {
                    body: operator_rpc::CommittedEntryResponse {
                        batch_id,
                        change_root,
                        lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();

        // The first withheld pass alarms, the second is latched, and the epoch keeps retrying.
        let first = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(first.withheld, [0]);
        assert!(first.reconciled.is_empty() && first.convicted.is_empty());
        assert!(first.unenforceable.is_empty());
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);
        let second = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert!(second.is_empty());
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);

        // Served evidence self-heals the withheld latch into the terminal verdict.
        let third = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(third.unenforceable, [0]);
        assert!(third.withheld.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        operator_server.await.unwrap();
    });
}

/// (a) Happy path: pairs are fetched incrementally, verified, persisted, survive restart,
/// and the certifiably finalized epoch reconciles cleanly and is durably marked. The
/// committed-side evidence is served by a real operator reconstructing the close from its
/// retained log.
#[test]
fn verified_incoming_reconciles_and_survives_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        operator.pay(0, 1, 3).unwrap();
        let result = operator.complete_close(44).unwrap();
        finalize(&control, &result).await;

        // The successor epoch finalizes before the receiver reconciles. A finalized close
        // stays reconstructable through the retention window, so the honest operator still
        // serves the predecessor's evidence instead of tripping the withholding alarm.
        register(&control, &mut operator).await;
        operator.pay(0, 2, 1).unwrap();
        let successor = operator.complete_close(45).unwrap();
        finalize(&control, &successor).await;

        // The reconstructed committed-side evidence matches the finalized roots, so the
        // certified anchor below names the exact close the operator serves lookups for.
        let evidence = operator
            .committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0)
            .unwrap();
        assert_eq!(evidence.change_root, result.roots.change);

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            for _ in 0..3 {
                relay(&mut operator_listener, &mut operator).await;
            }
        });

        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        let ledger = bob.incoming();
        assert_eq!(ledger.count, 2);
        assert_eq!(ledger.total, 8);
        let cursor = ledger.cursor;

        // A second intake is incremental: nothing new is fetched and the cursor holds.
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming(), ledger);
        assert_eq!(bob.incoming().cursor, cursor);

        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.reconciled, [0]);
        assert_eq!(bob.last_reconciled_epoch(), Some(0));
        drop(bob);

        // The held pairs, cursor, and reconciled mark all survive a restart.
        let recovered = Agent::open(database.path(), 1).unwrap();
        assert_eq!(recovered.incoming().count, 2);
        assert_eq!(recovered.incoming().total, 8);
        assert_eq!(recovered.incoming().cursor, cursor);
        assert_eq!(recovered.last_reconciled_epoch(), Some(0));
        assert!(
            recovered
                .store
                .unreconciled_incoming_epochs()
                .unwrap()
                .is_empty()
        );
        operator_server.await.unwrap();
    });
}

/// A finalized epoch whose committed evidence aged out of the operator's retention window
/// before the receiver reconciled it is decided as unavailable, never alarmed as withheld: the
/// honest operator legitimately no longer reconstructs the close, so the epoch is recorded
/// durably instead of retried.
#[test]
fn evidence_past_the_retention_window_is_unavailable_not_withheld() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();

        // Bob's credit lands in epoch 0, and its payer keeps moving in every later epoch, so
        // finalizing the epoch that closes the window shadows and prunes the versions
        // reconstructing epoch 0 needs.
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let held = operator.complete_close(50).unwrap();
        finalize(&control, &held).await;
        for epoch in 1..=Operator::RETAINED_EPOCHS + 1 {
            register(&control, &mut operator).await;
            operator.pay(0, 2, 1).unwrap();
            let result = operator.complete_close(50 + epoch).unwrap();
            assert_eq!(result.epoch, epoch);
            finalize(&control, &result).await;
        }
        assert_eq!(
            status(&control).await.last_finalized,
            Some(Operator::RETAINED_EPOCHS + 1)
        );
        assert!(
            operator
                .committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0)
                .is_err()
        );

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            for _ in 0..2 {
                relay(&mut operator_listener, &mut operator).await;
            }
        });

        // The served receipt still anchors to the epoch-0 registration, but the committed
        // side is gone: the epoch is decided as unavailable, durably and without a retry.
        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().total, 5);
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.unavailable, [0]);
        assert!(summary.withheld.is_empty() && summary.unenforceable.is_empty());
        assert!(summary.reconciled.is_empty() && summary.convicted.is_empty());
        assert_eq!(bob.last_reconciled_epoch(), None);
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        drop(bob);
        let recovered = Agent::open(database.path(), 1).unwrap();
        assert!(
            recovered
                .store
                .unreconciled_incoming_epochs()
                .unwrap()
                .is_empty()
        );
        operator_server.await.unwrap();
    });
}

/// (b) Crash windows: the cursor and pairs are durable before any reliance, and a refetch of
/// the same page is idempotent, so a lost response never duplicates or loses a credit.
#[test]
fn incoming_intake_is_durable_and_refetch_is_idempotent() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;

        // The receipt binds the certifiably registered epoch-0 context, so intake
        // anchors it against the chain's own registration record.
        let registered = registered_context(&control).await;
        let alice = &wallets()[0];
        let bob = wallets()[1].public_key();
        let receipt = issued_receipt(&registered, alice, &bob, 5);
        let invoice = Sha256::hash(&[receipt.ack.body().encode().as_ref()]);

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let served = receipt.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // Both intakes see the same page, standing in for a lost commit that refetches.
            for _ in 0..2 {
                let served = served.clone();
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::IncomingPayments(_)
                    ));
                    rpc::Response::Success {
                        body: incoming_response(&[(served, 1)]).encode(),
                    }
                })
                .await;
            }
        });

        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().count, 1);
        assert_eq!(bob.incoming().total, 5);
        drop(bob);

        // The receipt and cursor are durable before any reliance, so the reopened wallet
        // holds them, and the receiver service-accounting query answers from that held
        // evidence.
        let mut recovered = Agent::open(database.path(), 1).unwrap();
        assert_eq!(recovered.incoming().count, 1);
        assert_eq!(recovered.incoming().cursor, 1);
        let credit = recovered
            .paid(&alice.public_key(), &invoice)
            .unwrap()
            .unwrap();
        assert_eq!(credit.amount, 5);

        // Refetching the exact page reinserts nothing and leaves the ledger unchanged.
        recovered
            .intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(recovered.incoming().count, 1);
        assert_eq!(recovered.incoming().total, 5);
        operator_server.await.unwrap();
    });
}

/// Item 3: the censorship-fallback exit. When the operator will not carry a signed withdrawal,
/// the wallet escalates the exact retained request and its head opening directly to the chain,
/// where its certified applied outcome makes it an on-chain obligation.
#[test]
fn signed_withdrawal_escalates_to_settlement() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let genesis_root = status(&control).await.state_root;
        let account = wallets()[0].public_key();
        let mut agent = Agent::open(database.path(), 0).unwrap();

        // A vanished operator: it serves one head opening and then disappears, so the
        // withdrawal application fails and returns Signed with the opening retained.
        let opening = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN)
            .unwrap()
            .withdrawal_opening(&account)
            .unwrap();
        let opening_body = operator_rpc::WithdrawalOpeningResponse {
            root: opening.root,
            opening: opening.opening,
        }
        .encode();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalOpening(_)
                ));
                rpc::Response::Success { body: opening_body }
            })
            .await;
        });

        let outcome = agent
            .withdraw(
                &context,
                &mut chain,
                operator_address,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, .. } = outcome else {
            panic!("the vanished operator unexpectedly applied the withdrawal");
        };
        operator_server.await.unwrap();

        // Escalation queues the exact retained request as a certified chain
        // obligation.
        let escalated = agent
            .escalate_withdrawal(&context, &mut chain)
            .await
            .unwrap();
        assert_eq!(escalated, request);
        assert!(matches!(
            control
                .record(crate::chain::state::withdrawal_key(&deployment(), &account))
                .await,
            Some(Record::Withdrawal(queued)) if queued == request
        ));
        assert_eq!(genesis_root.digest, *request.body().state_root());

        // The claim slot opens durably: the operator may have applied the request and lost only
        // the response, and the carried claim must stay recoverable across a restart.
        assert!(agent.pending_withdrawal_claim.is_some());
        drop(agent);
        let reopened = Agent::open(database.path(), 0).unwrap();
        assert!(reopened.pending_withdrawal_claim.is_some());
    });
}

/// (d) Payer regression guard: the receiver intake and reconciliation are additive. A wallet
/// holding no incoming credits touches neither operator nor chain during reconciliation,
/// and the empty receiver ledger survives the schema across a restart.
#[test]
fn payer_flow_is_unaffected_by_receiver_state() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let payer = Agent::open(database.path(), 0).unwrap();
        assert_eq!(payer.incoming(), IncomingSummary::default());
        assert_eq!(payer.last_reconciled_epoch(), None);
        drop(payer);

        // Reconciliation with no held credits is a pure no-op: the unreachable operator and
        // chain are never dialed, so the payer path can never be gated by it.
        let mut chain = dead_client(&context);
        let mut payer = Agent::open(database.path(), 0).unwrap();
        let summary = payer
            .reconcile(&context, &mut chain, SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        assert!(summary.is_empty());
        assert_eq!(payer.incoming(), IncomingSummary::default());
        assert_eq!(payer.last_reconciled_epoch(), None);
        drop(payer);

        // The additive schema leaves the reopened payer's empty receiver ledger intact.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.incoming(), IncomingSummary::default());
        assert_eq!(recovered.last_reconciled_epoch(), None);
    });
}

/// With the operator unreachable, the balance poll and the withdrawal open the
/// wallet's leaf through its slice holders, verified against the certified
/// head. Before any close finalizes that is the genesis state. After one
/// finalizes, the holders have released its dealing, and the same root is
/// opened from the admitted successor's predecessor state instead.
#[test]
fn head_and_withdrawal_use_slice_holders_with_operator_unreachable() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let genesis_root = status(&control).await.state_root;
        let account = wallets()[0].public_key();

        // The poll retains the holder-served genesis leaf. No context was served,
        // so nothing is cached for signing.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            INITIAL_BALANCE
        );
        assert!(
            agent
                .store
                .recovery_opening(&genesis_root)
                .unwrap()
                .is_some()
        );
        assert!(agent.cache.is_none());

        // The withdrawal signs over that retained head and escalates to the chain.
        let outcome = agent
            .withdraw(
                &context,
                &mut chain,
                UNREACHABLE,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, .. } = outcome else {
            panic!("the unreachable operator applied the withdrawal");
        };
        assert_eq!(request.body().state_root(), &genesis_root.digest);
        assert_eq!(
            agent
                .escalate_withdrawal(&context, &mut chain)
                .await
                .unwrap(),
            request
        );
        assert!(matches!(
            control
                .record(withdrawal_key(&deployment(), &account))
                .await,
            Some(Record::Withdrawal(queued)) if queued == request
        ));

        // A wallet that never polled signs over an opening the withdrawal itself
        // fetched from the holders.
        let mut passive = Agent::new(1).unwrap();
        assert!(
            passive
                .store
                .recovery_opening(&genesis_root)
                .unwrap()
                .is_none()
        );
        let outcome = passive
            .withdraw(&context, &mut chain, UNREACHABLE, WithdrawalAction::Close)
            .await
            .unwrap();
        assert!(matches!(outcome, WithdrawalOutcome::Signed { .. }));
        assert!(
            passive
                .store
                .recovery_opening(&genesis_root)
                .unwrap()
                .is_some()
        );

        // The operator carries the queued request and the epoch finalizes: the
        // head moves to the finalized successor root, whose dealing the holders
        // release at finalization.
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator.apply_withdrawal(request).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let result = operator.complete_close(60).unwrap();
        finalize(&control, &result).await;
        let released = format!(
            "{:#}",
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap_err()
        );
        assert!(released.contains("released the dealing"), "{released}");

        // Once the successor close is admitted, its predecessor state is the same
        // finalized root, retained through its own window.
        register(&control, &mut operator).await;
        operator.pay(1, 2, 1).unwrap();
        let successor = operator.complete_close(61).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&successor)),
        )
        .await;
        let finalized_root = status(&control).await.state_root;
        assert_eq!(finalized_root, result.finalized.successor_root);
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            INITIAL_BALANCE - 7 - 5
        );
        assert!(
            agent
                .store
                .recovery_opening(&finalized_root)
                .unwrap()
                .is_some()
        );
    });
}

/// THE POINT of validator-served evidence: the operator refuses every lookup,
/// and the receiver still files the `HigherAckEntry` challenge from the payer's
/// slice holders' committed entry, which the chain proves. The operator is not
/// on the enforcement path at all.
#[test]
fn reconcile_convicts_with_validator_served_lookup_while_operator_withholds() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let fixture = admit_omitting(&control).await;
        let batch_id = admitted_batch(&fixture);
        let bob_receipt = fixture.held_receipt.clone();

        // The operator delivers Bob's receipt and refuses everything else for as
        // long as it is asked.
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let withheld = Arc::new(AtomicUsize::new(0));
        let counter = withheld.clone();
        context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_receipt, 1)]).encode(),
                }
            })
            .await;
            loop {
                let refused = refuse(&mut operator_listener).await;
                assert!(matches!(
                    refused,
                    operator_rpc::OperatorRequest::CommittedEntry(_)
                ));
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().total, 5);

        // The holders' committed entry verifies against the admitted change root
        // and the held receipt exceeds it: convicted, with the deployment faulted
        // on the proven challenge and no lookup ever requested from the operator.
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.convicted, [0]);
        assert!(chain.status(&context).await.unwrap().hard_faulted);
        assert!(matches!(
            control.record(fault_key(&deployment())).await,
            Some(Record::Fault(FaultRecord::Faulted(
                HardFaultReasonResponse::ProvenChallenge { batch_id: proven, .. }
            ))) if proven == batch_id
        ));
        assert_eq!(withheld.load(Ordering::Relaxed), 0);
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
    });
}

/// Claim evidence is fetched from the slice holders inside the challenge
/// window, verified against the admitted roots and cached, and the claim
/// completes after finalization with no operator anywhere. A wallet that
/// missed the window finds the dealing released and waits for the operator.
#[test]
fn claim_evidence_fetched_during_window_claims_after_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        operator.pay(1, operator.wallet_count(), 40).unwrap();
        let result = operator.complete_close(71).unwrap();
        let batch = result.header.batch_id::<Sha256>();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;

        // Inside the window both claims cache holder-served evidence naming the
        // admitted batch, and settlement cannot release them yet.
        let mut alice = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut alice);
        let waiting = alice
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(format!("{waiting:#}").contains("has not finalized"));
        let held = alice.pending_withdrawal_claim.clone().unwrap();
        assert_eq!(
            held.evidence.as_ref().map(|evidence| evidence.batch_id),
            Some(batch)
        );
        assert!(held.result.is_none());
        drop(alice);

        let mut receiver = Agent::new(wallets().len()).unwrap();
        let waiting = receiver
            .claim_external_payout(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(format!("{waiting:#}").contains("has not finalized"));
        assert_eq!(
            receiver
                .pending_payout_claim
                .as_ref()
                .and_then(|held| held.evidence.as_ref())
                .map(|evidence| evidence.batch_id),
            Some(batch)
        );

        // The cached copy survives a restart and, once the batch finalizes,
        // releases against its certified claim roots.
        finalize(&control, &result).await;
        let mut alice = Agent::open(database.path(), 0).unwrap();
        assert!(
            alice
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_some())
        );
        let release = alice
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(release.amount, 25);
        assert!(alice.pending_withdrawal_claim.is_none());
        let payout = receiver
            .claim_external_payout(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(payout.amount, 40);
        assert_eq!(payout.receiver, external_identity().key);
        assert!(receiver.pending_payout_claim.is_none());

        // The window closed: a wallet that missed it finds no open window and
        // depends on the operator's reconstruction.
        let mut late = Agent::new(0).unwrap();
        open_withdrawal_intent(&mut late);
        let error = late
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("fetch withdrawal evidence"));
    });
}

/// A holder that answers garbage, undecodable bytes or an opening that does not
/// verify, is skipped for the next holder, and the holder that served is
/// remembered for the account.
#[test]
fn garbage_holder_is_skipped_and_next_holder_serves() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_distinct_holders(&context, &control, 9_700);
        let account = wallets()[0].public_key();
        let order = Holders::default().order(&chain, &account).unwrap();
        assert_eq!(order.len(), 3);

        let garbage = garbage_holder(
            &context,
            order[0],
            rpc::Response::Success {
                body: Bytes::from_static(b"not an evidence response"),
            },
        )
        .await;
        let mut forged = genesis_cache().opening(&account).unwrap();
        forged.leaf.state.balance += 1;
        let forger = garbage_holder(
            &context,
            order[1],
            rpc::Response::Success {
                body: EvidenceResponse::Served(Evidence::Genesis(forged)).encode(),
            },
        )
        .await;
        let honest = forwarding_holder(&context, order[2]).await;

        let mut agent = Agent::new(0).unwrap();
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            INITIAL_BALANCE
        );
        assert_eq!(garbage.load(Ordering::Relaxed), 1);
        assert_eq!(forger.load(Ordering::Relaxed), 1);
        assert_eq!(honest.load(Ordering::Relaxed), 1);

        // The serving holder is remembered: the next read goes straight to it.
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            INITIAL_BALANCE
        );
        assert_eq!(garbage.load(Ordering::Relaxed), 1);
        assert_eq!(forger.load(Ordering::Relaxed), 1);
        assert_eq!(honest.load(Ordering::Relaxed), 2);
    });
}

/// Dead holders are rotated past until the last one serves, and exhausting
/// every holder is an error naming each address tried.
#[test]
fn only_the_last_holder_answers() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_distinct_holders(&context, &control, 9_700);
        let account = wallets()[0].public_key();
        let order = Holders::default().order(&chain, &account).unwrap();
        assert_eq!(order.len(), 3);

        let last = forwarding_holder(&context, order[2]).await;
        let mut agent = Agent::new(0).unwrap();
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            INITIAL_BALANCE
        );
        assert_eq!(last.load(Ordering::Relaxed), 1);

        let mut dead = client_with_distinct_holders(&context, &control, 9_800);
        let dead_order = Holders::default().order(&dead, &account).unwrap();
        let mut stranded = Agent::new(0).unwrap();
        let error = format!(
            "{:#}",
            stranded
                .balance(&context, &mut dead, UNREACHABLE)
                .await
                .unwrap_err()
        );
        for holder in dead_order {
            assert!(error.contains(&holder.to_string()), "{error}");
        }
    });
}

/// A wallet passive across the final finalization has no opening retained at
/// the frozen root. Recovery opens it through the slice holders, verified
/// against the frozen state root, and claims. Dead holders leave the claim
/// unsubmitted.
#[test]
fn hard_fault_recovery_fetches_the_frozen_root_opening() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let account = wallets()[0].public_key();
        let frozen_root = status(&control).await.state_root;

        // A registered epoch expires unadmitted, freezing the deployment at the
        // genesis head.
        let _registered = registered_context(&control).await;
        let height = control.advance(0).await;
        let mut faulted = status(&control).await;
        while !faulted.hard_faulted {
            let advanced = control.advance(1).await;
            assert!(advanced < height + 30, "the deployment never faulted");
            faulted = status(&control).await;
        }
        assert_eq!(faulted.state_root, frozen_root);

        let passive = Agent::new(0).unwrap();
        assert!(
            passive
                .store
                .recovery_opening(&frozen_root)
                .unwrap()
                .is_none()
        );
        let release = passive
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap();
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, INITIAL_BALANCE);

        let mut dead = client_with_holders(&context, &control, UNREACHABLE);
        let stranded = Agent::new(1).unwrap();
        let error = stranded
            .recover_hard_fault(&context, &mut dead)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("validators opened none"));
        assert!(
            control
                .record(crate::chain::state::hard_fault_key(
                    &deployment(),
                    &wallets()[1].public_key()
                ))
                .await
                .is_none()
        );
    });
}

/// The operator-dark walkthrough: the operator accepts sends and refuses
/// everything else. The wallet still withdraws through settlement over a
/// holder-served opening, pays under the chain-registered context with a
/// holder-served floor, and claims the finalized withdrawal from the slice
/// holders' evidence, with the refused acknowledgement holding nothing open.
#[test]
fn operator_dark_wallet_escalates_pays_and_claims_through_validators() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let genesis_root = status(&control).await.state_root;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The head opening and the withdrawal are refused: the wallet opens its
        // genesis leaf through the holders, signs over it, and escalates.
        let withdrawing = context.child("withdrawing").spawn(move |_| async move {
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::WithdrawalOpening(_)
            ));
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::ApplyWithdrawal(_)
            ));
            listener
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let outcome = agent
            .withdraw(
                &context,
                &mut chain,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
            )
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, .. } = outcome else {
            panic!("the dark operator applied the withdrawal");
        };
        assert_eq!(request.body().state_root(), &genesis_root.digest);
        assert!(
            agent
                .store
                .recovery_opening(&genesis_root)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            agent
                .escalate_withdrawal(&context, &mut chain)
                .await
                .unwrap(),
            request
        );
        let mut listener = withdrawing.await.unwrap();

        // The queued request is a chain obligation the operator's registration
        // must carry verbatim.
        operator.apply_withdrawal(request).unwrap();
        register(&control, &mut operator).await;

        // The head is refused, so the wallet signs under the chain's registered
        // context with the holders' opening as its floor. The operator has
        // nothing left to do but accept the send, whose registration the
        // certified anchor confirms.
        let paying = context.child("paying").spawn(move |_| async move {
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::PaymentHead(_)
            ));
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let payment = accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.total, 7);
        assert_eq!(agent.cumulative_debit, 7);
        assert!(agent.cache.is_none());
        let (mut listener, mut operator) = paying.await.unwrap();

        // The close carrying the withdrawal is admitted: inside its window the
        // holders serve the claim, verified against the admitted roots and cached,
        // while settlement cannot release it yet. The operator is not asked.
        let result = operator.complete_close(80).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        let waiting = agent
            .claim_withdrawal(&context, &mut chain, address)
            .await
            .unwrap_err();
        assert!(format!("{waiting:#}").contains("has not finalized"));
        assert!(agent.pending_withdrawal_claim.as_ref().is_some_and(|held| {
            held.evidence
                .as_ref()
                .is_some_and(|evidence| evidence.batch_id == result.header.batch_id::<Sha256>())
        }));

        // After finalization the cached claim releases against the certified
        // batch, and the refused acknowledgement holds nothing open.
        finalize(&control, &result).await;
        let acknowledging = context.child("acknowledging").spawn(move |_| async move {
            assert!(matches!(
                refuse(&mut listener).await,
                operator_rpc::OperatorRequest::AcknowledgeWithdrawal(_)
            ));
        });
        let release = agent
            .claim_withdrawal(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(release.amount, 5);
        assert_eq!(release.destination.as_ref(), agent.name().as_bytes());
        assert!(agent.pending_withdrawal_claim.is_none());
        acknowledging.await.unwrap();
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 7);
        assert!(recovered.pending_withdrawal_claim.is_none());
    });
}
