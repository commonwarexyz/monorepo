use super::{
    custody::{DEPOSIT_ID_NAMESPACE, withdrawal_deadline},
    evidence::Holders,
    fixtures::{StateFixture, TempDatabase},
    store::{IncomingSummary, PendingWithdrawalClaim},
    *,
};
use crate::{
    chain::{
        client::{Chain as _, Client},
        harness,
        query::{
            Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse, Lookup, METHOD_EVIDENCE,
            METHOD_READ, ReadRequest,
        },
        state::{
            FaultRecord, HardFaultReasonResponse, Record, RegistrationRecord, admitted_key,
            anchor_key, deposit_key, fault_key, registration_key, status_key, withdrawal_key,
        },
        tx::{
            AdmitRequest, BeginHardFaultSettlementRequest, ChallengeRequest, RegisterEpochRequest,
            SettlementTx, WithdrawalClaimRequest,
        },
    },
    operator::{Operator, rpc as operator_rpc},
    protocol::{
        Acceptance, AcceptedEntry, Ack, DepositEvent, Entry, INITIAL_BALANCE, Key,
        MAX_ACCEPTANCE_BYTES, MAX_ENTRIES, Protocol, Receipt, SettlementResult, Wallet, deployment,
        identities, operator_key, wallets,
    },
    rpc,
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch},
    challenge::{AckWitness, Challenge, EntryWitness, HigherEntryLookup},
    payment::{PaymentContext, SendAuthorization, VECTOR_ACK_SIGNATURE_NAMESPACE, VectorSendBody},
    qmdb::{StateLookup, StateOpening, StateRoot, StateValueOpening},
    transition::{ActivityRange, BatchId, EpochContext, WithdrawalClaim},
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::{
    Clock as _, Listener as _, Network, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{TestRng, sync::Mutex};
use std::{
    fs::File,
    io,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

fn signed_deposit(
    control: &harness::Control,
    event: DepositEvent,
) -> crate::chain::tx::DepositRequest {
    let wallet = wallets()
        .into_iter()
        .find(|wallet| wallet.public_key() == event.account)
        .unwrap();
    crate::chain::tx::DepositRequest::sign(
        control.identity().native.chain_id(),
        deployment(),
        event,
        wallet.signer(),
    )
}

fn epoch_fee(control: &harness::Control) -> u64 {
    let native = &control.identity().native;
    let entry = native
        .deployments
        .iter()
        .find(|entry| entry.deployment.digest() == &deployment())
        .unwrap();
    native.epoch_fee * u64::from(entry.max_dealing_bytes).div_ceil(1024)
}

/// The in-process chain's query address.
const CHAIN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_600);

/// An address nothing ever binds: the unreachable operator, and the dead
/// holder every evidence request fails against.
const UNREACHABLE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_602);

fn activity_range(result: &SettlementResult) -> ActivityRange<Digest> {
    result.roots.activity_range(&result.context).unwrap()
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
/// can put a distinct server behind every validator.
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

fn client_with_query_and_holders(
    context: &deterministic::Context,
    control: &harness::Control,
    query: SocketAddr,
    holder: SocketAddr,
) -> Client {
    let mut genesis = control.identity().clone();
    for validator in &mut genesis.validators {
        validator.query = holder;
    }
    Client::new(
        &genesis,
        deployment(),
        vec![query],
        context.child("client_rng"),
    )
    .unwrap()
}

/// Forwards chain queries while counting descriptor and fault reads that a retired epoch cannot
/// make useful.
async fn query_counting_retired_evidence(
    context: &deterministic::Context,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let queried = Arc::new(AtomicUsize::new(0));
    let counter = queried.clone();
    let mut listener = context
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    context
        .child("query_counting_retired_evidence")
        .spawn(move |context| async move {
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                if request.method == METHOD_READ
                    && matches!(
                        ReadRequest::decode(request.body.clone()),
                        Ok(ReadRequest {
                            lookup: Lookup::Admitted { .. } | Lookup::Fault,
                            ..
                        })
                    )
                {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                let response = rpc::call(&context, CHAIN, &request).await.unwrap();
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    (address, queried)
}

/// Serves evidence at `address` by forwarding every request to the chain,
/// counting the requests served.
async fn forwarding_holder(
    context: &deterministic::Context,
    address: SocketAddr,
    delay: Duration,
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
                context.sleep(delay).await;
                let response = rpc::call(&context, CHAIN, &request).await.unwrap();
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    served
}

/// Forwards native pages and every proof except one payout position.
async fn payout_holder_refusing_position(
    context: &deterministic::Context,
    address: SocketAddr,
    refused: u64,
) -> Arc<AtomicUsize> {
    let refused_count = Arc::new(AtomicUsize::new(0));
    let counted = refused_count.clone();
    let mut listener = context.bind(address).await.unwrap();
    context
        .child("payout_holder_refusing_position")
        .spawn(move |context| async move {
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                let response = if request.method == METHOD_EVIDENCE
                    && matches!(
                        EvidenceRequest::decode(request.body.clone()),
                        Ok(EvidenceRequest {
                            lookup: EvidenceLookup::Payout { index, .. },
                            ..
                        }) if index == refused
                    ) {
                    counted.fetch_add(1, Ordering::Relaxed);
                    rpc::Response::Success {
                        body: EvidenceResponse::Absent.encode(),
                    }
                } else {
                    rpc::call(&context, CHAIN, &request).await.unwrap()
                };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    refused_count
}

/// Serves retained native evidence without a parallel archive.
async fn source_holder(context: &deterministic::Context) -> SocketAddr {
    let mut listener = context
        .bind(SocketAddr::from(([127, 0, 0, 1], 9_850)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    context
        .child("source_holder")
        .spawn(move |context| async move {
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                let response = match EvidenceRequest::decode(request.body.clone()) {
                    Ok(EvidenceRequest {
                        lookup:
                            EvidenceLookup::Account { .. } | EvidenceLookup::CommittedEntry { .. },
                        ..
                    }) => rpc::call(&context, CHAIN, &request).await.unwrap(),
                    _ => rpc::Response::Success {
                        body: EvidenceResponse::Absent.encode(),
                    },
                };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    address
}

/// Consumes one payout immediately before serving its second certified status read.
async fn consuming_payout_status_query(
    context: &deterministic::Context,
    control: harness::Control,
    index: u64,
    start: u64,
    claim: WithdrawalClaim<Digest>,
) -> SocketAddr {
    let mut listener = context
        .bind(SocketAddr::from(([127, 0, 0, 1], 9_851)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    context
        .child("consuming_payout_status_query")
        .spawn(move |context| async move {
            let mut consumed = false;
            let mut reads = 0;
            loop {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                if request.method == METHOD_READ
                    && matches!(
                        ReadRequest::decode(request.body.clone()),
                        Ok(ReadRequest {
                            lookup: Lookup::Unclaimed { index: found },
                            ..
                        }) if found == index
                    )
                {
                    reads += 1;
                }
                if reads == 2 && !consumed {
                    control
                        .submit(SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                            deployment: deployment(),
                            start,
                            claim: claim.clone(),
                        }))
                        .await;
                    consumed = true;
                }
                let response = rpc::call(&context, CHAIN, &request).await.unwrap();
                rpc::send_response(&mut sink, &response).await.unwrap();
            }
        });
    address
}

/// Refuses the status refresh after discovery authenticated one unspent payout.
async fn failing_second_payout_status_query(
    context: &deterministic::Context,
    index: u64,
) -> SocketAddr {
    let mut listener = context
        .bind(SocketAddr::from(([127, 0, 0, 1], 9_852)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    context
        .child("failing_second_payout_status_query")
        .spawn(move |context| async move {
            let mut reads = 0;
            loop {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                if request.method == METHOD_READ
                    && matches!(
                        ReadRequest::decode(request.body.clone()),
                        Ok(ReadRequest {
                            lookup: Lookup::Unclaimed { index: found },
                            ..
                        }) if found == index
                    )
                {
                    reads += 1;
                }
                let response = if reads >= 2 {
                    rpc::Response::Error {
                        error: Bytes::from_static(b"status unavailable"),
                    }
                } else {
                    rpc::call(&context, CHAIN, &request).await.unwrap()
                };
                rpc::send_response(&mut sink, &response).await.unwrap();
            }
        });
    address
}

/// Serves native activity while selectively withholding entry openings.
async fn selective_source_holder(
    context: &deterministic::Context,
    withhold_after: usize,
    withhold_count: usize,
    refused_payer: Option<Key>,
) -> SocketAddr {
    let mut listener = context
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    context
        .child("selective_source_holder")
        .spawn(move |context| async move {
            let mut entries = 0;
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                let response = match EvidenceRequest::decode(request.body.clone()) {
                    Ok(EvidenceRequest {
                        lookup: EvidenceLookup::CommittedEntry { payer, .. },
                        ..
                    }) => {
                        let ordinal = entries;
                        entries += 1;
                        if refused_payer.as_ref() == Some(&payer)
                            || (withhold_after..withhold_after + withhold_count).contains(&ordinal)
                        {
                            rpc::Response::Success {
                                body: EvidenceResponse::Absent.encode(),
                            }
                        } else {
                            rpc::call(&context, CHAIN, &request).await.unwrap()
                        }
                    }
                    _ => rpc::Response::Success {
                        body: EvidenceResponse::Absent.encode(),
                    },
                };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    address
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
    let (_, withdrawals) = operator.registration_boundary().unwrap();
    let mut queued = Vec::new();
    for request in withdrawals.requests() {
        if matches!(control.record(withdrawal_key(&deployment(), request.account())).await,
            Some(Record::Withdrawal(recorded)) if recorded == *request)
        {
            queued.push(request.clone());
        }
    }
    let queued = WithdrawalBatch::new(queued).unwrap();
    let request = operator.signed_registration(&queued).unwrap();
    applied(control, &SettlementTx::RegisterEpoch(request)).await;
    let record = registration_record(control).await;
    operator.adopt_registration(&record).unwrap();
    operator.registration_boundary().unwrap().0
}

/// Admits `result`'s close and drives the chain past its challenge window to
/// certified finalization.
async fn finalize(control: &harness::Control, result: &SettlementResult) {
    applied(control, &SettlementTx::Admit(AdmitRequest::from(result))).await;
    let deadline = result.context.epoch_context().challenge_deadline();
    let height = control.advance(0).await;
    if height <= deadline {
        control.advance(deadline - height + 1).await;
    }
    let status = status(control).await;
    assert!(
        status
            .last_finalized
            .is_some_and(|last| last >= result.context.payment().epoch())
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
async fn registered_context(control: &harness::Control) -> EpochContext<Key, Digest> {
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let deposits_root = DepositBatch::<Key>::empty().root::<Sha256>().unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let signature =
        protocol.sign_chain_registration(0, 400, &deposits_root, &withdrawals, epoch_fee(control));
    applied(
        control,
        &SettlementTx::RegisterEpoch(RegisterEpochRequest {
            fee: epoch_fee(control),
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,

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
pub(super) fn issued_receipt(
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

/// Opens a claim intent around the exact authorization the wallet must retain.
fn stage_withdrawal_intent(agent: &mut Agent, request: &SignedWithdrawal<Key, Digest>) {
    let root = StateRoot::new(*request.body().state_root());
    let genesis = genesis_cache();
    assert_eq!(root, genesis.root(), "fixture withdrawal is not at genesis");
    let opening = genesis.opening(&agent.account()).unwrap();
    stage_withdrawal_intent_at(agent, request, opening);
}

fn stage_withdrawal_intent_at(
    agent: &mut Agent,
    request: &SignedWithdrawal<Key, Digest>,
    opening: StateOpening<Key, Digest>,
) {
    let root = StateRoot::new(*request.body().state_root());
    agent
        .store
        .retain_recovery_opening(&root, &opening)
        .unwrap();
    agent.store.stage_withdrawal(request).unwrap();
    agent.pending_withdrawal = Some(request.clone());
    agent.pending_withdrawal_claim = None;
}

fn settlement_withdrawal(
    operator: &Operator,
    result: &crate::protocol::SettlementResult,
    withdrawals: &WithdrawalBatch<Key, Digest>,
    account: &Key,
) -> (SignedWithdrawal<Key, Digest>, u64, WithdrawalClaim<Digest>) {
    let request = withdrawals
        .request_for(account)
        .expect("settlement has the requested withdrawal")
        .clone();
    let ordinal = withdrawals
        .requests()
        .iter()
        .position(|candidate| candidate.account() == account)
        .unwrap();
    let position =
        result.context.predecessor_logs().payouts.operations + u64::try_from(ordinal).unwrap();
    let claim = operator
        .payout_proof(result.roots.withdrawal_outputs, position)
        .unwrap();
    assert_eq!(claim.position(), position);
    let output = claim
        .verify::<Sha256>(&result.roots.withdrawal_outputs)
        .unwrap();
    assert_eq!(
        output.destination().as_ref(),
        request.body().destination().as_ref()
    );
    (request, position, claim)
}

/// The four-identity genesis account state the chain certifies at its root.
fn genesis_cache() -> StateFixture {
    StateFixture::new(
        identities()
            .into_iter()
            .map(|identity| (identity.key, INITIAL_BALANCE))
            .collect(),
    )
}

fn unregistered_context(operator: Key, epoch: u64) -> EpochContext<Key, Digest> {
    crate::protocol::epoch_context_at(
        deployment(),
        operator,
        epoch,
        &DepositBatch::empty(),
        &WithdrawalBatch::empty(),
        400,
        100,
        101,
    )
    .unwrap()
}

/// A scripted payment head over the certified genesis root: the served state
/// is operator-claimed display data, and the opening is the wallet's genuine
/// genesis row.
fn payment_head_response(
    context: EpochContext<Key, Digest>,
    balance: u64,
) -> operator_rpc::PaymentHeadResponse {
    let account = wallets()[0].public_key();
    let cache = genesis_cache();
    operator_rpc::PaymentHeadResponse {
        context,
        balance,
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
        let payment_context_epoch = registered_context(&control).await;
        let payment_context = payment_context_epoch.payment().clone();
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
                    body: payment_head_response(payment_context_epoch.clone(), 100).encode(),
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
fn unresolved_intent_keeps_exact_bytes_across_hostile_epoch_hints_and_reopen() {
    for (committed, receipts, zero_net) in [
        (false, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let control = harness::start_with_native(
                &context,
                CHAIN,
                "chain",
                harness::native(crate::protocol::deployments()),
                crate::protocol::Timing {
                    admission_offset: 100,
                    challenge_duration: 100,
                },
            )
            .await;
            let mut chain = client_with_holders(&context, &control, CHAIN);
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let staging = context.child("staging").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                if committed {
                    accept_and_drop(&mut listener, &mut operator).await;
                } else {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    assert!(matches!(
                        operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                            .unwrap(),
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }
                (listener, operator)
            });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(
                agent
                    .pay(&context, &mut chain, address, &[(1, 7)])
                    .await
                    .is_err()
            );
            let original = agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .clone();
            drop(agent);
            let (mut listener, operator) = staging.await.unwrap();
            let expected = original.clone();
            let hint = PaymentContext::new(
                Sha256::hash(&[b"hostile-successor"]),
                old.epoch() + 1,
                operator_key(),
            );
            let hostile = context
                .child("hostile_correction")
                .spawn(move |_| async move {
                    for _ in 0..crate::chain::client::SUBMIT_ATTEMPTS {
                        respond(&mut listener, |request| {
                            let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                                panic!("ambiguous intent requested a fresh head or authorization");
                            };
                            assert_eq!(request.authorization.encode(), expected.encode());
                            rpc::Response::Success {
                                body: stale_response(&hint, 0),
                            }
                        })
                        .await;
                    }
                    (listener, operator)
                });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .resume_pending_payment(&context, &mut chain, address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("repeatedly rejected"));
            assert_eq!(
                agent.pending_payment.as_ref().unwrap().authorization,
                original
            );
            assert_eq!(agent.store.debits_since(0).unwrap(), 0);
            drop(agent);
            let (mut listener, mut operator) = hostile.await.unwrap();
            if zero_net {
                operator.pay(1, 0, 7).unwrap();
            } else if !committed {
                operator.pay(1, 2, 1).unwrap();
            }
            let result = operator.complete_close(31).unwrap();
            finalize(&control, &result).await;
            let live = register(&control, &mut operator).await;
            let hint = live.clone();

            // Unavailable evidence is not authenticated absence and cannot free the slot.
            let unavailable = context
                .child("unavailable_activity")
                .spawn(move |_| async move {
                    respond(&mut listener, |_| rpc::Response::Success {
                        body: stale_response(&hint, 0),
                    })
                    .await;
                    (listener, operator)
                });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let mut isolated = client_with_holders(&context, &control, UNREACHABLE);
            assert!(
                agent
                    .resume_pending_payment(&context, &mut isolated, address)
                    .await
                    .is_err()
            );
            assert_eq!(
                agent
                    .pending_payment
                    .as_ref()
                    .unwrap()
                    .authorization
                    .encode(),
                original.encode()
            );
            drop(agent);
            let (mut listener, mut operator) = unavailable.await.unwrap();
            let hint = live.clone();
            let expected = original.clone();
            let resolution = context
                .child("authenticated_resolution")
                .spawn(move |_| async move {
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                            panic!("expected exact retry");
                        };
                        assert_eq!(request.authorization, expected);
                        rpc::Response::Success {
                            body: stale_response(&hint, 0),
                        }
                    })
                    .await;
                    if committed {
                        respond(&mut listener, |request| {
                            let operator_rpc::OperatorRequest::AcceptedBatch(request) = request
                            else {
                                panic!("expected optional receipts");
                            };
                            assert_eq!(request.authorization, expected);
                            if receipts {
                                operator_rpc::handle_decoded(
                                    &mut operator,
                                    operator_rpc::OperatorRequest::AcceptedBatch(request),
                                )
                            } else {
                                rpc::Response::Success {
                                    body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                                }
                            }
                        })
                        .await;
                    } else {
                        relay(&mut listener, &mut operator).await;
                        respond(&mut listener, |request| {
                            let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                                panic!("expected resolved fresh intent");
                            };
                            assert_eq!(request.authorization.body().epoch(), hint.epoch());
                            assert_eq!(request.authorization.body().seq(), 1);
                            assert_eq!(request.authorization.body().cumulative_debit(), 7);
                            operator_rpc::handle_decoded(
                                &mut operator,
                                operator_rpc::OperatorRequest::AcceptSend(request),
                            )
                        })
                        .await;
                    }
                    (listener, operator)
                });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let outcome = agent
                .resume_pending_payment(&context, &mut chain, address)
                .await
                .unwrap()
                .unwrap();
            if committed && !receipts {
                assert!(matches!(
                    outcome,
                    PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
                ));
            } else {
                let outcome = accepted(outcome);
                assert_eq!(
                    outcome.epoch,
                    if committed { old.epoch() } else { live.epoch() }
                );
            }
            assert!(agent.pending_payment.is_none());
            assert_eq!(agent.store.debits_since(0).unwrap(), 7);
            drop(agent);
            let (mut listener, mut operator) = resolution.await.unwrap();
            let next = context
                .child("next_epoch_payment")
                .spawn(move |_| async move {
                    if committed {
                        relay(&mut listener, &mut operator).await;
                    }
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                            panic!("expected next payment");
                        };
                        assert_eq!(request.authorization.body().epoch(), live.epoch());
                        assert_eq!(
                            request.authorization.body().seq(),
                            1 + u64::from(!committed)
                        );
                        assert_eq!(
                            request.authorization.body().cumulative_debit(),
                            if committed { 3 } else { 10 }
                        );
                        operator_rpc::handle_decoded(
                            &mut operator,
                            operator_rpc::OperatorRequest::AcceptSend(request),
                        )
                    })
                    .await;
                });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            accepted(
                agent
                    .pay(&context, &mut chain, address, &[(1, 3)])
                    .await
                    .unwrap(),
            );
            assert_eq!(agent.store.debits_since(0).unwrap(), 10);
            next.await.unwrap();
        });
    }
}

#[test]
fn finalized_payment_without_a_saved_ack_remains_pending_after_retirement() {
    for committed in [false, true] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = context.child("lost_response").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                if committed {
                    accept_and_drop(&mut listener, &mut operator).await;
                } else {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, operator_rpc::METHOD_ACCEPT_SEND);
                }
                operator
            });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(
                agent
                    .pay(&context, &mut chain, address, &[(1, 7)])
                    .await
                    .is_err()
            );
            assert!(agent.pending_payment.is_some());
            drop(agent);
            let mut operator = server.await.unwrap();
            if !committed {
                operator.pay(1, 2, 1).unwrap();
            }
            let result = operator.complete_close(31).unwrap();
            finalize(&control, &result).await;

            // A successor can retire the descriptor before a lost acknowledgement is resolved.
            // Without retained coverage, the exact durable authorization remains pending.
            register(&control, &mut operator).await;
            operator.pay(2, 3, 1).unwrap();
            let successor = operator.complete_close(32).unwrap();
            finalize(&control, &successor).await;
            assert!(
                control
                    .record(admitted_key(&deployment(), 0))
                    .await
                    .is_none()
            );
            assert!(control.record(anchor_key(&deployment(), 0)).await.is_none());

            let mut unavailable = client_with_holders(&context, &control, UNREACHABLE);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(
                agent
                    .resume_pending_payment(&context, &mut unavailable, UNREACHABLE)
                    .await
                    .is_err()
            );
            assert!(agent.pending_payment.is_some());
            drop(agent);

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let resolved = agent
                .resume_pending_payment(&context, &mut chain, UNREACHABLE)
                .await;
            assert!(resolved.is_err());
            assert!(agent.pending_payment.is_some());
            assert_eq!(agent.store.debits_since(0).unwrap(), 0);
            drop(agent);
            let recovered = Agent::open(database.path(), 0).unwrap();
            assert!(recovered.pending_payment.is_some());
        });
    }
}

#[test]
fn immutable_anchor_conflict_releases_only_the_invalid_context() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let registered_epoch = registered_context(&control).await;
        let registered = registered_epoch.payment().clone();
        let fake_epoch = unregistered_context(operator_key(), registered.epoch());
        let fake = fake_epoch.payment().clone();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let serving = registered.clone();
        let server = context
            .child("corrective_anchor")
            .spawn(move |_| async move {
                respond(&mut listener, |_| rpc::Response::Success {
                    body: payment_head_response(fake_epoch, 100).encode(),
                })
                .await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                        panic!("expected stale authorization");
                    };
                    assert_eq!(request.authorization.body().anchor(), fake.anchor());
                    rpc::Response::Success {
                        body: stale_response(&serving, 0),
                    }
                })
                .await;
                respond(&mut listener, |_| rpc::Response::Success {
                    body: payment_head_response(registered_epoch.clone(), 100).encode(),
                })
                .await;
                respond_acceptance(
                    &mut listener,
                    &Wallet::from_seed("operator", 1),
                    &serving,
                    7,
                    Vec::new(),
                )
                .await;
            });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let paid = accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(paid.acceptance.ack.body().anchor(), registered.anchor());
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert!(agent.pending_payment.is_none());
        assert_eq!(
            agent.store.vector_state(&registered).unwrap().unwrap().seq,
            1
        );
        server.await.unwrap();
    });
}

#[test]
fn registration_read_lag_keeps_exact_intent_until_anchor_conflict_is_visible() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let mut before_registration = Vec::new();
        for lookup in [
            Lookup::Status,
            Lookup::Anchor { epoch: 0 },
            Lookup::Registration,
        ] {
            let request = ReadRequest::new(deployment(), lookup);
            before_registration.push((request.encode(), control.read(request).await.encode()));
        }
        let corrections = Arc::new(AtomicUsize::new(0));
        let observed = corrections.clone();
        let mut query_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let query_address = query_listener.local_addr().unwrap();
        let query_control = control.clone();
        context
            .child("lagging_registration")
            .spawn(move |_| async move {
                loop {
                    let (_, mut sink, mut stream) = query_listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, crate::chain::query::METHOD_READ);
                    let body = if observed.load(Ordering::Relaxed) < 3 {
                        before_registration
                            .iter()
                            .find(|(key, _)| *key == request.body)
                            .expect("unresolved intent only reads its settlement context")
                            .1
                            .clone()
                    } else {
                        query_control
                            .read(ReadRequest::decode(request.body).unwrap())
                            .await
                            .encode()
                    };
                    rpc::send_response(&mut sink, &rpc::Response::Success { body })
                        .await
                        .unwrap();
                }
            });
        let mut chain = Client::new(
            control.identity(),
            deployment(),
            vec![query_address],
            context.child("lagging_rng"),
        )
        .unwrap();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let head = operator.payment_head(&wallets()[0].public_key()).unwrap();
        let old = head.context.payment().clone();
        let live = register(&control, &mut operator).await;
        assert_ne!(old.anchor(), live.anchor());
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context
            .child("corrective_registration")
            .spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentHead(_)
                    ));
                    rpc::Response::Success {
                        body: payment_head_response(head.context, 100).encode(),
                    }
                })
                .await;
                let mut expected = None;
                for _ in 0..3 {
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptSend(send) = &request else {
                            panic!("registration absence must retain the exact authorization");
                        };
                        assert_eq!(send.authorization.body().anchor(), old.anchor());
                        let bytes = send.encode();
                        assert_eq!(&bytes, expected.get_or_insert(bytes.clone()));
                        corrections.fetch_add(1, Ordering::Relaxed);
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                }
                relay(&mut listener, &mut operator).await;
                relay(&mut listener, &mut operator).await;
            });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let started = context.current();
        let payment = accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert!(
            context.current().duration_since(started).unwrap() >= crate::chain::client::POLL * 2
        );
        assert_eq!(payment.acceptance.ack.body().anchor(), live.anchor());
        assert_eq!(payment.acceptance.entries[0].cumulative, 7);
        assert_eq!(payment.acceptance.entries[0].count, 1);
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.pending_payment.is_none());
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert!(agent.pending_payment.is_none());
        server.await.unwrap();
    });
}

#[test]
fn received_sequence_zero_is_valid_and_survives_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let payment_epoch = registered_context(&control).await;
        let payment = payment_epoch.payment().clone();
        let payer = wallets().remove(0);
        let receiver = wallets()[1].public_key();
        let mut receipt = issued_receipt(&payment, &payer, &receiver, 7);
        let body = VectorSendBody::new(
            &payment,
            payer.public_key(),
            0,
            7,
            receipt.ack.body().send_root(),
        );
        receipt.ack = Ack::sign_by_authorities(
            body,
            payer.signer(),
            Protocol::new(NonZeroUsize::MIN).unwrap().operator(),
        );
        let id = Sha256::hash(&[&receipt.ack.body().encode()]);
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context
            .child("zero_sequence_receipt")
            .spawn(move |_| async move {
                respond(&mut listener, |_| rpc::Response::Success {
                    body: incoming_response(&[(receipt, 1)]).encode(),
                })
                .await;
            });
        let mut agent = Agent::open(database.path(), 1).unwrap();
        agent
            .intake_incoming(&context, &mut chain, address)
            .await
            .unwrap();
        assert!(agent.has_receipt(&payer.public_key(), &id).unwrap());
        drop(agent);
        let agent = Agent::open(database.path(), 1).unwrap();
        assert_eq!(agent.incoming().total, 7);
        assert!(agent.has_receipt(&payer.public_key(), &id).unwrap());
        server.await.unwrap();
    });
}

#[test]
fn zero_balance_then_held_credit_reuses_the_same_epoch_vector_after_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let epoch = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let staging = context.child("spend_to_zero").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 100)])
                .await
                .unwrap(),
        );
        let (mut listener, mut operator) = staging.await.unwrap();
        operator.pay(1, 0, 7).unwrap();
        let receiving = context.child("fund_and_spend").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("held credit should fund the local fast path without a head read");
                };
                assert_eq!(request.authorization.body().seq(), 2);
                assert_eq!(request.authorization.body().cumulative_debit(), 107);
                operator_rpc::handle_decoded(
                    &mut operator,
                    operator_rpc::OperatorRequest::AcceptSend(request),
                )
            })
            .await;
        });
        agent
            .intake_incoming(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(agent.incoming().total, 7);
        drop(agent);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .unwrap(),
        );
        let retained = agent.store.vector_state(&epoch).unwrap().unwrap();
        assert_eq!(retained.seq, 2);
        assert_eq!(retained.entries[0].cumulative, 107);
        assert_eq!(retained.entries[0].count, 2);
        receiving.await.unwrap();
    });
}

#[test]
fn finalized_zero_balance_preserves_accepted_epoch_state() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let epoch = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context.child("spend_balance").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            operator
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 100)])
                .await
                .unwrap(),
        );
        let mut operator = server.await.unwrap();
        let result = operator.complete_close(34).unwrap();
        finalize(&control, &result).await;
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            0
        );
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        let retained = agent.store.vector_state(&epoch).unwrap().unwrap();
        assert_eq!(retained.seq, 1);
        assert_eq!(retained.cumulative_debit, 100);
    });
}

#[test]
fn withdrawal_escalation_uses_finalized_balance_across_pending_closes() {
    deterministic::Runner::default().start(|context| async move {
        let control = harness::start_with_native(
            &context,
            CHAIN,
            "chain",
            harness::native(crate::protocol::deployments()),
            crate::protocol::Timing {
                admission_offset: 100,
                challenge_duration: 100,
            },
        )
        .await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        for epoch in 0..6 {
            register(&control, &mut operator).await;
            operator.pay(1, 2, 1).unwrap();
            let result = operator.complete_close(35 + epoch).unwrap();
            applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        }
        assert!(status(&control).await.last_finalized.is_none());
        for epoch in 0..6 {
            assert!(
                !chain
                    .admitted(&context, epoch)
                    .await
                    .unwrap()
                    .unwrap()
                    .finalized
            );
        }
        let mut agent = Agent::new(0).unwrap();
        let action = WithdrawalAction::Amount(NonZeroU64::new(25).unwrap());
        let outcome = agent
            .withdraw(&context, &mut chain, UNREACHABLE, action)
            .await
            .unwrap();
        assert!(matches!(outcome, WithdrawalOutcome::Signed { .. }));
        let request = agent
            .escalate_withdrawal(&context, &mut chain)
            .await
            .unwrap();
        assert_eq!(
            chain.withdrawal(&context, agent.account()).await.unwrap(),
            Some(request)
        );
        assert!(status(&control).await.last_finalized.is_none());
    });
}

#[test]
fn finalized_activity_requires_its_actual_batch_root_and_account() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 7).unwrap();
        let result = operator.complete_close(32).unwrap();
        finalize(&control, &result).await;
        let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
        let account = wallets()[0].public_key();
        let lookup = Holders::default()
            .committed_account_at(&context, &chain, 0, &admitted.activity_range(), &account)
            .await
            .unwrap();
        assert!(
            lookup
                .resolve::<Sha256>(&admitted.activity_range(), &account)
                .unwrap()
                .1
                .is_some()
        );
        assert!(
            lookup
                .resolve::<Sha256>(&admitted.activity_range(), &wallets()[1].public_key())
                .is_err()
        );
        let forged_address = SocketAddr::from(([127, 0, 0, 1], 9_703));
        let forged = garbage_holder(
            &context,
            forged_address,
            rpc::Response::Success {
                body: EvidenceResponse::Served(Evidence::Account(lookup.clone())).encode(),
            },
        )
        .await;
        let forged_chain = client_with_holders(&context, &control, forged_address);
        let mut wrong_batch = admitted;
        wrong_batch.roots.change.root = Sha256::hash(&[b"wrong-activity-root"]);
        assert!(
            Holders::default()
                .committed_account_at(
                    &context,
                    &forged_chain,
                    0,
                    &wrong_batch.activity_range(),
                    &account,
                )
                .await
                .is_err()
        );
        assert!(forged.load(Ordering::Relaxed) > 0);
        let mut wrong = admitted.activity_range();
        wrong.head.root = Sha256::hash(&[b"wrong-activity-root"]);
        assert!(lookup.resolve::<Sha256>(&wrong, &account).is_err());
    });
}

#[test]
fn unfinalized_included_activity_cannot_resolve_an_ambiguous_intent() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let old = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert!(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .is_err()
        );
        let expected = agent
            .pending_payment
            .as_ref()
            .unwrap()
            .authorization
            .clone();
        let (mut listener, mut operator) = staging.await.unwrap();
        let result = operator.complete_close(33).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        let response = context.child("pending_close").spawn(move |_| async move {
            respond(&mut listener, |_| rpc::Response::Success {
                body: stale_response(&old, 7),
            })
            .await;
        });
        let error = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("has not finalized"));
        assert!(status(&control).await.last_finalized.is_none());
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
        assert_eq!(agent.receipt_count(), 0);
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.pending_payment.unwrap().authorization, expected);
        response.await.unwrap();
    });
}

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
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
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
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.cache.as_ref().unwrap().context, live);
        paying.await.unwrap();
    });
}

#[test]
fn deterministically_rejected_sends_are_never_staged() {
    deterministic::Runner::default().start(|context| async move {
        let (_control, mut chain) = chain(&context).await;
        let head_context = unregistered_context(operator_key(), 0);
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
                    body: payment_head_response(head_context.clone(), 100).encode(),
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
        let payment_context_epoch = registered_context(&control).await;
        let payment_context = payment_context_epoch.payment().clone();
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
                    body: payment_head_response(payment_context_epoch.clone(), 100).encode(),
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
        assert_eq!(agent.store.debits_since(0).unwrap(), 10);
        drop(agent);

        // The cache is durable, so the restarted wallet also signs locally.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        accepted(
            recovered
                .pay(&context, &mut chain, operator_address, &[(1, 2)])
                .await
                .unwrap(),
        );
        assert_eq!(recovered.store.debits_since(0).unwrap(), 12);
        assert_eq!(recovered.receipt_count(), 3);
        operator_server.await.unwrap();

        // Each live acceptance verifies its anchor, admission absence, registration,
        // and recent status. Only the first payment reads a head; none submit to settlement.
        let (reads, submissions) = control.counts().await;
        assert_eq!(reads - baseline.0, 13);
        assert_eq!(submissions - baseline.1, 0);
    });
}

#[test]
fn fresh_wallet_falls_back_to_one_head_read_and_caches_the_context() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context_epoch = registered_context(&control).await;
        let payment_context = payment_context_epoch.payment().clone();
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
                    body: payment_head_response(payment_context_epoch.clone(), 100).encode(),
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
fn admitted_activity_exclusion_allows_a_new_epoch_intent() {
    for (finalized, prior_accepted) in [(true, true), (true, false), (false, true), (false, false)]
    {
        deterministic::Runner::default().start(|context| async move {
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let operator_address = listener.local_addr().unwrap();

            let staging = context.child("staging").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                if prior_accepted {
                    relay(&mut listener, &mut operator).await;
                } else {
                    assert!(matches!(
                        refuse(&mut listener).await,
                        operator_rpc::OperatorRequest::AcceptSend(_)
                    ));
                }
                (listener, operator)
            });
            let mut agent = Agent::new(0).unwrap();
            let first = agent
                .pay(&context, &mut chain, operator_address, &[(1, 7)])
                .await;
            if prior_accepted {
                let first = accepted(first.unwrap());
                assert_eq!(first.epoch, old.epoch());
                assert_eq!(first.acceptance.entries[0].cumulative, 7);
            } else {
                assert!(first.is_err());
                assert!(agent.pending_payment.is_some());
            }
            let prior_debit = if prior_accepted { 7 } else { 0 };
            assert_eq!(agent.store.debits_since(0).unwrap(), prior_debit);
            let (mut listener, mut operator) = staging.await.unwrap();

            // The admitted close either contains the earlier accepted body or no payer activity.
            operator.pay(2, 3, 1).unwrap();
            let result = operator.complete_close(11).unwrap();
            if finalized {
                finalize(&control, &result).await;
            } else {
                applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
            }
            let live = register(&control, &mut operator).await;
            assert_eq!(live.epoch(), 1);
            let admitted = chain
                .admitted(&context, old.epoch())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(admitted.finalized, finalized);
            let lookup = Holders::default()
                .committed_account_at(
                    &context,
                    &chain,
                    old.epoch(),
                    &admitted.activity_range(),
                    &agent.account(),
                )
                .await
                .unwrap();
            let (_, activity) = lookup
                .resolve::<Sha256>(&admitted.activity_range(), &agent.account())
                .unwrap();
            assert_eq!(
                activity.is_some_and(|activity| activity.has_outgoing()),
                prior_accepted
            );

            // The old epoch excludes the new staged authorization. The fresh epoch starts at zero.
            let rolling = context.child("rolling").spawn(move |_| async move {
                for _ in 0..4 {
                    relay(&mut listener, &mut operator).await;
                }
            });
            let amount = if prior_accepted { 3 } else { 7 };
            let payment = accepted(
                agent
                    .pay(&context, &mut chain, operator_address, &[(1, amount)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.epoch, live.epoch());
            assert_eq!(payment.acceptance.entries[0].cumulative, amount);
            assert_eq!(payment.acceptance.entries[0].count, 1);
            assert_eq!(agent.store.debits_since(0).unwrap(), prior_debit + amount);
            assert!(agent.pending_payment.is_none());

            // Adoption moved the signing context forward and kept the verified floor.
            let cache = agent.cache.as_ref().unwrap();
            assert_eq!(cache.context, live);
            assert_eq!(cache.epoch, live.epoch());

            let payment = accepted(
                agent
                    .pay(&context, &mut chain, operator_address, &[(1, 2)])
                    .await
                    .unwrap(),
            );
            assert_eq!(payment.epoch, live.epoch());
            assert_eq!(payment.acceptance.entries[0].cumulative, amount + 2);
            assert_eq!(payment.acceptance.entries[0].count, 2);
            assert_eq!(
                agent.store.debits_since(0).unwrap(),
                prior_debit + amount + 2
            );
            assert_eq!(agent.receipt_count(), if prior_accepted { 3 } else { 2 });
            assert_eq!(
                status(&control).await.last_finalized,
                finalized.then_some(old.epoch())
            );
            rolling.await.unwrap();
        });
    }
}

#[test]
fn delayed_admission_retries_the_exact_intent_until_successor_payment_completes() {
    for entries in [vec![(1, 3)], vec![(1, 3), (2, 4)]] {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let total = entries.iter().map(|(_, amount)| amount).sum::<u64>();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let staging = context.child("staging").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                relay(&mut listener, &mut operator).await;
                (listener, operator)
            });
            let mut agent = Agent::new(0).unwrap();
            accepted(
                agent
                    .pay(&context, &mut chain, address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            let (mut listener, mut operator) = staging.await.unwrap();
            let delayed_control = control.clone();
            let rolling = context
                .child("delayed_admission")
                .spawn(move |context| async move {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(request) =
                        operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                            .unwrap()
                    else {
                        panic!("the second payment must sign from the cached epoch");
                    };
                    assert_eq!(request.authorization.body().epoch(), old.epoch());
                    assert_eq!(request.authorization.body().seq(), 2);
                    assert_eq!(request.authorization.body().cumulative_debit(), 7 + total);
                    let expected = request.encode();
                    let result = operator.complete_close(12).unwrap();
                    let response = operator_rpc::handle_decoded(
                        &mut operator,
                        operator_rpc::OperatorRequest::AcceptSend(request),
                    );
                    rpc::send_response(&mut sink, &response).await.unwrap();

                    // Admission is unavailable while the wallet receives corrective responses.
                    let admit_at = context.current() + Duration::from_secs(1);
                    let mut corrections = 1;
                    let (mut sink, request) = loop {
                        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                        let operator_rpc::OperatorRequest::AcceptSend(request) =
                            operator_rpc::decode_request(
                                rpc::recv_request(&mut stream).await.unwrap(),
                            )
                            .unwrap()
                        else {
                            panic!("the unresolved payment must retry its exact authorization");
                        };
                        assert_eq!(request.encode(), expected);
                        if context.current() >= admit_at {
                            break (sink, request);
                        }
                        let response = operator_rpc::handle_decoded(
                            &mut operator,
                            operator_rpc::OperatorRequest::AcceptSend(request),
                        );
                        rpc::send_response(&mut sink, &response).await.unwrap();
                        corrections += 1;
                    };
                    assert!(corrections >= 3);
                    applied(
                        &delayed_control,
                        &SettlementTx::Admit(AdmitRequest::from(&result)),
                    )
                    .await;
                    let live = register(&delayed_control, &mut operator).await;
                    let response = operator_rpc::handle_decoded(
                        &mut operator,
                        operator_rpc::OperatorRequest::AcceptSend(request),
                    );
                    rpc::send_response(&mut sink, &response).await.unwrap();
                    relay(&mut listener, &mut operator).await;
                    relay(&mut listener, &mut operator).await;
                    live
                });
            let started = context.current();
            let payment = accepted(
                agent
                    .pay(&context, &mut chain, address, &entries)
                    .await
                    .unwrap(),
            );
            let live = rolling.await.unwrap();
            assert!(context.current().duration_since(started).unwrap() >= Duration::from_secs(1));
            assert_eq!(payment.epoch, live.epoch());
            assert_eq!(payment.epoch, 1);
            assert_eq!(payment.total, total);
            assert_eq!(payment.acceptance.entries.len(), entries.len());
            for (recipient, amount) in &entries {
                let entry = payment
                    .acceptance
                    .entries
                    .iter()
                    .find(|entry| entry.recipient == wallets()[*recipient].public_key())
                    .unwrap();
                assert_eq!(entry.cumulative, *amount);
                assert_eq!(entry.count, 1);
            }
            assert_eq!(agent.store.debits_since(0).unwrap(), 7 + total);
            assert_eq!(agent.receipt_count(), 1 + entries.len() as u64);
            assert!(agent.pending_payment.is_none());
            assert!(status(&control).await.last_finalized.is_none());
            assert!(
                !chain
                    .admitted(&context, 0)
                    .await
                    .unwrap()
                    .unwrap()
                    .finalized
            );
        });
    }
}

#[test]
fn unaffordable_by_local_view_is_refused_before_staging() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context_epoch = registered_context(&control).await;
        let payment_context = payment_context_epoch.payment().clone();
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
                    body: payment_head_response(payment_context_epoch.clone(), 100).encode(),
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
                    body: payment_head_response(payment_context_epoch.clone(), 93).encode(),
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
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);

        let payment = accepted(
            agent
                .pay(&context, &mut chain, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.total, 3);
        assert_eq!(payment.acceptance.entries[0].cumulative, 10);
        assert_eq!(agent.store.debits_since(0).unwrap(), 10);
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_deadline_caps_at_the_clock_horizon() {
    assert_eq!(
        withdrawal_deadline(7, &crate::protocol::Timing::GENESIS).unwrap(),
        7 + crate::protocol::settlement_config(&crate::protocol::Timing::GENESIS)
            .unwrap()
            .maximum_withdrawal_notice
            .get()
    );
    assert_eq!(
        withdrawal_deadline(u64::MAX - 20, &crate::protocol::Timing::GENESIS).unwrap(),
        u64::MAX
    );
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
        let chain_id = chain.genesis().native.chain_id();
        let native_before = chain
            .native_balance(&context, chain_id, agent.account())
            .await
            .unwrap();

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
        assert_eq!(applied, event.event);
        assert!(agent.pending_deposit.is_none());
        assert_eq!(agent.deposit_nonce, 1);
        control.submit(SettlementTx::Deposit(event)).await;
        assert_eq!(
            chain
                .native_balance(&context, chain_id, agent.account())
                .await
                .unwrap(),
            native_before - 7
        );
        assert_eq!(status(&control).await.custody, 407);
    });
}

#[test]
fn fresh_native_wallet_database_reopens() {
    let database = TempDatabase::new();
    let account = {
        let agent = Agent::open(database.path(), 0).unwrap();
        agent.account()
    };
    let reopened = Agent::open(database.path(), 0).unwrap();
    assert_eq!(reopened.account(), account);
    assert!(reopened.pending_deposit.is_none());
    assert!(reopened.pending_transfer.is_none());
}

#[test]
fn native_transfer_survives_restart_and_debits_once() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let chain_id = chain.genesis().native.chain_id();
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let from = agent.account();
        let to = crate::protocol::operator_key();
        let before = chain
            .native_balance(&context, chain_id, from.clone())
            .await
            .unwrap();
        let recipient_before = chain
            .native_balance(&context, chain_id, to.clone())
            .await
            .unwrap();
        let mut dead = dead_client(&context);
        agent
            .transfer_native(&context, &mut dead, to.clone(), 17)
            .await
            .unwrap_err();
        let staged = agent.pending_transfer.clone().unwrap();
        let exact_bytes = staged.encode();
        control
            .submit(SettlementTx::NativeTransfer(staged.clone()))
            .await;
        assert_eq!(
            chain
                .native_transfer(&context, chain_id, from.clone(), staged.id)
                .await
                .unwrap(),
            Some(staged.clone())
        );
        assert_eq!(
            chain
                .native_balance(&context, chain_id, from.clone())
                .await
                .unwrap(),
            before - 17
        );
        drop(agent);
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            recovered.pending_transfer.as_ref().unwrap().encode(),
            exact_bytes
        );
        let receipt = recovered
            .transfer_native(&context, &mut chain, to.clone(), 17)
            .await
            .unwrap();
        assert_eq!(receipt, staged);
        control.submit(SettlementTx::NativeTransfer(staged)).await;
        assert_eq!(
            chain
                .native_balance(&context, chain_id, from)
                .await
                .unwrap(),
            before - 17
        );
        assert_eq!(
            chain.native_balance(&context, chain_id, to).await.unwrap(),
            recipient_before + 17
        );
        assert!(recovered.pending_transfer.is_none());
        drop(recovered);
        assert!(
            Agent::open(database.path(), 0)
                .unwrap()
                .pending_transfer
                .is_none()
        );
    });
}

#[test]
fn deposit_accepts_a_funded_key_absent_from_the_deployment_genesis() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut funder = Agent::new(0).unwrap();
        let mut agent = Agent::new(4).unwrap();
        funder
            .transfer_native(&context, &mut chain, agent.account(), 7)
            .await
            .unwrap();
        let event = agent.deposit(&context, &mut chain, 7).await.unwrap();
        assert_eq!(event.account, agent.account());
        assert_eq!(event.amount, 7);
        assert!(agent.pending_deposit.is_none());
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
            &SettlementTx::Deposit(signed_deposit(
                &control,
                DepositEvent {
                    id,
                    account: account.clone(),
                    amount: 9,
                },
            )),
        )
        .await;
        assert_eq!(status(&control).await.custody, 409);

        // The wallet observes the foreign binding on the certified record
        // and discards the staged event instead of retrying it forever.
        let error = agent.deposit(&context, &mut chain, 7).await.unwrap_err();
        assert!(format!("{error:#}").contains("certifiably bound to another event"));
        assert!(agent.pending_deposit.is_none());
        assert_eq!(status(&control).await.custody, 409);

        let fresh = agent.deposit(&context, &mut chain, 7).await.unwrap();
        assert_ne!(fresh.id, id);
        assert_eq!(status(&control).await.custody, 416);
    });
}

#[test]
fn withdrawal_response_loss_and_wrong_ack_preserve_one_exact_request() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
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
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let first = agent
            .withdraw(&context, &mut chain, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, error } = first else {
            panic!("lost operator response unexpectedly applied withdrawal");
        };
        assert!(format!("{error:#}").contains("apply operator withdrawal"));
        assert!(agent.pending_withdrawal.is_some());
        drop(agent);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        assert!(agent.cache.is_none());

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
        drop(agent);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        assert!(agent.cache.is_none());

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
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_uses_only_the_exact_retained_head_when_the_operator_is_unreachable() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let account = wallets()[0].public_key();
        let current = genesis_cache();
        let stale = StateFixture::new(vec![(account.clone(), 99)]);
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
        // the operator or the validators, and refuses to sign when neither
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
        let payment_context = unregistered_context(impostor.public_key(), 7);
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
                    body: payment_head_response(payment_context, 100).encode(),
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
        assert_eq!(recovered.store.debits_since(0).unwrap(), 0);
        assert!(recovered.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

#[derive(Clone, Copy, Debug)]
enum HeadUse {
    Pay,
    Balance,
    Finalized,
}

#[test]
fn foreign_deployment_head_cannot_authorize_payment() {
    foreign_deployment_head_cannot_authorize(HeadUse::Pay);
}

#[test]
fn foreign_deployment_balance_cannot_cache_payment_context() {
    foreign_deployment_head_cannot_authorize(HeadUse::Balance);
}

#[test]
fn foreign_deployment_finalized_head_cannot_cache_payment_context() {
    foreign_deployment_head_cannot_authorize(HeadUse::Finalized);
}

fn foreign_deployment_head_cannot_authorize(usage: HeadUse) {
    deterministic::Runner::timed(std::time::Duration::from_secs(120)).start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let native = &control.identity().native;
        let payer = wallets().remove(0);
        let recipient = wallets().remove(1).public_key();
        let registration = crate::chain::tx::RegisterDeploymentRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"same-key foreign deployment"]),
            crate::protocol::operator_ack_key(0),
            native.deployments[0].network_key.clone(),
            1024 * 1024,
            native.registration_fee,
            &crate::protocol::operator_signer(0),
        );
        let foreign = registration.deployment_id();
        control
            .submit(SettlementTx::RegisterDeployment(registration))
            .await;
        let mut other =
            Client::new(control.identity(), foreign, vec![CHAIN], TestRng::new(72)).unwrap();
        let selected = chain.registered(&context).await.unwrap();
        let registered = other.registered(&context).await.unwrap();
        assert_ne!(selected.deployment.digest(), registered.deployment.digest());
        assert_eq!(selected.deployment.operator, registered.deployment.operator);

        let event = DepositEvent {
            id: Sha256::hash(&[b"foreign deployment funding"]),
            account: payer.public_key(),
            amount: 100,
        };
        control
            .submit(SettlementTx::Deposit(
                crate::chain::tx::DepositRequest::sign(
                    native.chain_id(),
                    foreign,
                    event.clone(),
                    payer.signer(),
                ),
            ))
            .await;
        assert_eq!(other.status(&context).await.unwrap().custody, 100);
        let protocol = Protocol::with_signer(
            NonZeroUsize::MIN,
            foreign,
            crate::protocol::operator_signer(0),
            crate::protocol::operator_ack_signer(0),
        )
        .unwrap();
        let deposits = DepositBatch::new(vec![
            commonware_clearing::bajillion::boundary::DepositRecord::new(payer.public_key(), 100)
                .unwrap(),
        ])
        .unwrap();
        let root = deposits.root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let fee = native.epoch_fee * u64::from(registered.max_dealing_bytes).div_ceil(1024);
        control
            .submit(SettlementTx::RegisterEpoch(RegisterEpochRequest {
                deployment: foreign,
                epoch: 0,
                predecessor_liability: 0,
                deposits_root: root,

                withdrawals: withdrawals.clone(),
                openings: Vec::new(),
                fee,
                signature: protocol.sign_chain_registration(0, 0, &root, &withdrawals, fee),
            }))
            .await;
        let registered = other.registration(&context).await.unwrap().unwrap();
        let epoch = protocol
            .registration_at(
                0,
                deposits,
                withdrawals,
                0,
                registered.admission_deadline,
                registered.challenge_deadline,
            )
            .unwrap();
        assert_eq!(
            other.anchor(&context, 0).await.unwrap(),
            Some(*epoch.context.payment().anchor())
        );
        let head = payment_head_response(epoch.context.clone(), 100);
        let selected_root = head.root;
        let captured = Arc::new(Mutex::new(None));
        let observed = captured.clone();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        context.child("foreign_head").spawn(move |_| async move {
            loop {
                respond(&mut listener, |request| match request {
                    operator_rpc::OperatorRequest::PaymentHead(_) => rpc::Response::Success {
                        body: head.encode(),
                    },
                    operator_rpc::OperatorRequest::AcceptSend(request) => {
                        *observed.lock() = Some(request);
                        rpc::Response::Error {
                            error: Bytes::from_static(b"response lost"),
                        }
                    }
                    _ => panic!("unexpected wallet request"),
                })
                .await;
            }
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        match usage {
            HeadUse::Pay => {}
            HeadUse::Balance => {
                let _ = agent.balance(&context, &mut chain, address).await;
            }
            HeadUse::Finalized => {
                let _ = agent.finalized_head(&context, &mut chain, address).await;
            }
        }
        drop(agent);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let _ = agent.pay(&context, &mut chain, address, &[(1, 7)]).await;
        let send = captured.lock().take();
        let emitted = send.is_some();
        if let Some(send) = send {
            // A captured authorization must settle through B's real funded boundary.
            let vector = OutVector::new(
                0,
                payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative: 7,
                    count: 1,
                }],
            )
            .unwrap();
            let terminal = commonware_clearing::bajillion::transition::Terminal {
                operator_signature: protocol.sign_ack_aggregate(send.authorization.body()),
                authorization: send.authorization,
                vector,
            };
            let state = crate::protocol::init_replica(
                context.child("foreign_balances"),
                "foreign-balances",
                protocol.strategy().clone(),
                Vec::new(),
            )
            .await
            .unwrap();
            let prepared = protocol.prepare(epoch, vec![terminal]).unwrap();
            let (result, prepared) = protocol
                .complete(prepared, &state, &mut TestRng::new(91))
                .await
                .unwrap();
            let state = state.apply(prepared).await.unwrap();
            let state = Box::pin(state.sync()).await.unwrap();
            control
                .submit(SettlementTx::Admit(AdmitRequest::from(&result)))
                .await;
            assert!(other.admitted(&context, 0).await.unwrap().is_some());
            let height = control.advance(0).await;
            control
                .advance(
                    result
                        .context
                        .epoch_context()
                        .challenge_deadline()
                        .saturating_sub(height)
                        + 1,
                )
                .await;
            let finalized = other.status(&context).await.unwrap();
            assert_eq!(finalized.last_finalized, Some(0));
            assert_eq!(finalized.state_root, state.state().root());
            assert_eq!(
                state
                    .state()
                    .opening(payer.public_key())
                    .await
                    .unwrap()
                    .balance
                    .get(),
                93
            );
            assert_eq!(
                state
                    .state()
                    .opening(recipient.clone())
                    .await
                    .unwrap()
                    .balance
                    .get(),
                7
            );
            assert_eq!(finalized.claimable, 0);
            assert_eq!(
                chain.status(&context).await.unwrap().state_root,
                selected_root
            );
        }
        assert!(
            !emitted,
            "{usage:?} authorized a debit in another registered deployment"
        );
        drop(agent);
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_payment.is_none());
        assert!(recovered.cache.is_none());
    });
}

#[derive(Clone, Copy, Debug)]
enum PaymentHeadGateCase {
    InvalidAnchor,
    MismatchedStateRoot,
    WrongAccount,
    ForgedBalance,
    ZeroBalance,
    InvalidProof,
    HardFaulted,
}

impl PaymentHeadGateCase {
    /// The hard-faulted case permanently faults the shared chain, so it runs
    /// last.
    const ALL: [Self; 7] = [
        Self::InvalidAnchor,
        Self::MismatchedStateRoot,
        Self::WrongAccount,
        Self::ForgedBalance,
        Self::ZeroBalance,
        Self::InvalidProof,
        Self::HardFaulted,
    ];

    const fn actor(self) -> &'static str {
        match self {
            Self::InvalidAnchor => "invalid_anchor",
            Self::MismatchedStateRoot => "mismatched_state_root",
            Self::WrongAccount => "wrong_account",
            Self::ForgedBalance => "forged_balance",
            Self::ZeroBalance => "zero_balance",
            Self::InvalidProof => "invalid_proof",
            Self::HardFaulted => "hard_faulted",
        }
    }

    const fn expected_error(self) -> &'static str {
        match self {
            Self::InvalidAnchor => "payment context is not bound to this deployment and operator",
            Self::MismatchedStateRoot => "payer opening is not the exact settlement head",
            Self::WrongAccount => "payer opening belongs to another account",
            Self::ForgedBalance => "verify payer Current state opening",
            Self::ZeroBalance => "insufficient available balance",
            Self::InvalidProof => "verify payer Current state opening",
            Self::HardFaulted => "settlement is permanently hard-faulted",
        }
    }

    /// Corrupts the served head. The settlement side is a certified read now,
    /// so every corruption lives in the operator's response.
    fn corrupt(self, head: &mut operator_rpc::PaymentHeadResponse) {
        match self {
            Self::InvalidAnchor => {
                let mut encoded = head.context.encode().to_vec();
                encoded[0] ^= 1;
                head.context = EpochContext::decode(encoded).unwrap();
            }
            Self::MismatchedStateRoot => {
                // A verifiable opening over a root that is not the certified
                // settlement head.
                let account = wallets()[0].public_key();
                let forked = StateFixture::new(vec![(account.clone(), 100)]);
                head.root = forked.root();
                head.opening = forked.opening(&account).unwrap();
            }
            Self::WrongAccount => {
                let account = wallets()[2].public_key();
                let cache = genesis_cache();
                head.opening = cache.opening(&account).unwrap();
            }
            Self::ForgedBalance => {
                head.opening.balance = NonZeroU64::new(head.opening.balance.get() + 1).unwrap()
            }
            Self::ZeroBalance => head.balance = 0,
            Self::InvalidProof => {
                head.opening.proof.proof.chunk[0] ^= 1;
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
                let registered_epoch = registered_context(&control).await;
                let registered = registered_epoch.payment().clone();
                let height = control.advance(0).await;
                let deadline = height + 12;
                control.advance(deadline - height + 1).await;
                assert!(status(&control).await.hard_faulted);
                let _ = registered;
            }
            let database = TempDatabase::new();
            let payment_context = unregistered_context(operator_key(), 0);
            let mut head = payment_head_response(payment_context, 100);
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
            assert_eq!(recovered.store.debits_since(0).unwrap(), 0, "{case:?}");
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
            &SettlementTx::Deposit(signed_deposit(
                &control,
                crate::protocol::DepositEvent {
                    id: Sha256::hash(&[b"other-anchor-deposit"]),
                    account: wallets()[1].public_key(),
                    amount: 1,
                },
            )),
        )
        .await;
        let signature = protocol.sign_chain_registration(
            0,
            400,
            &deposits_root,
            &withdrawals,
            epoch_fee(&control),
        );
        applied(
            &control,
            &SettlementTx::RegisterEpoch(RegisterEpochRequest {
                fee: epoch_fee(&control),
                deployment: deployment(),
                epoch: 0,
                predecessor_liability: 400,
                deposits_root,

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
            for expected in [
                operator_rpc::METHOD_PAYMENT_HEAD,
                operator_rpc::METHOD_ACCEPT_SEND,
            ] {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, expected);
                    let request = operator_rpc::decode_request(request).unwrap();
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
        assert!(error.contains("permanently excluded"));
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
        assert_eq!(agent.receipt_count(), 0);
        assert!(agent.pending_payment.is_none());
        assert!(agent.cache.is_none());

        operator_server.await.unwrap();
    });
}

#[test]
fn response_loss_restart_retries_byte_identical_pending_send() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context_epoch = registered_context(&control).await;
        let payment_context = payment_context_epoch.payment().clone();
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
                    body: payment_head_response(payment_context_epoch.clone(), 100).encode(),
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
        assert_eq!(recovered.store.debits_since(0).unwrap(), 7);
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
fn maximum_acceptance_survives_exact_retry_and_wallet_restart() {
    let database = TempDatabase::new();
    let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
    let total = u64::try_from(MAX_ENTRIES).unwrap();
    operator.deposit(0, total).unwrap();
    operator.complete_close(256).unwrap();
    let account = wallets()[0].public_key();
    let head = operator.payment_head(&account).unwrap();
    assert!(head.balance >= total);
    let mut deltas: Vec<_> = (0..MAX_ENTRIES)
        .map(|index| {
            (
                Wallet::from_seed("recipient", 30_000 + u64::try_from(index).unwrap()).public_key(),
                1,
            )
        })
        .collect();
    deltas.sort_by(|left, right| left.0.cmp(&right.0));
    for (recipient, _) in &deltas {
        assert!(operator.payment_head(recipient).is_err());
    }
    let (authorization, entries) = operator.sign_send(0, &deltas).unwrap();
    let mut agent = Agent::open(database.path(), 0).unwrap();
    agent
        .store
        .retain_recovery_opening(&head.root, &head.opening)
        .unwrap();
    agent
        .store
        .stage_payment(&authorization, &entries, &head.root, 0)
        .unwrap();
    let accepted = operator
        .accept_send(authorization.clone(), entries.clone())
        .unwrap()
        .into_accepted();
    accepted.acceptance.verify(head.context.payment()).unwrap();
    let encoded = accepted.acceptance.encode();
    assert_eq!(encoded.len(), 80_378);
    assert_eq!(
        Acceptance::decode(encoded.clone()).unwrap(),
        accepted.acceptance
    );

    // A response lost after operator commitment leaves the exact signed intent durable.
    drop(agent);
    let mut recovered = Agent::open(database.path(), 0).unwrap();
    let pending = recovered.pending_payment.clone().unwrap();
    assert_eq!(pending.authorization.encode(), authorization.encode());
    assert_eq!(pending.entries, entries);
    let retried = operator
        .accept_send(pending.authorization.clone(), pending.entries.clone())
        .unwrap()
        .into_accepted();
    assert_eq!(retried.acceptance.encode(), encoded);
    assert_eq!(
        recovered
            .store
            .commit_payment(
                &retried.acceptance,
                &pending.authorization,
                &pending.entries,
                0,
                0,
                false
            )
            .unwrap(),
        total
    );
    drop(recovered);

    let recovered = Agent::open(database.path(), 0).unwrap();
    assert!(recovered.pending_payment.is_none());
    assert_eq!(recovered.receipt_count(), total);
    assert_eq!(
        recovered
            .store
            .debits_since(head.context.payment().epoch())
            .unwrap(),
        total
    );
    let vector = recovered
        .store
        .vector_state(head.context.payment())
        .unwrap()
        .unwrap();
    assert_eq!(vector.seq, 1);
    assert_eq!(vector.cumulative_debit, total);
    assert_eq!(vector.entries.len(), MAX_ENTRIES);
    assert!(
        vector
            .entries
            .iter()
            .all(|entry| entry.cumulative == 1 && entry.count == 1)
    );
    assert_eq!(
        operator.payment_head(&account).unwrap().balance,
        head.balance - total
    );

    // The byte budget covers every structurally decodable opening; receipt verification
    // separately authenticates the path against the signed root.
    let mut full_depth = accepted.acceptance;
    for entry in &mut full_depth.entries {
        entry
            .opening
            .proof
            .siblings
            .resize(u32::BITS as usize, Sha256::hash(&[b"sibling"]));
    }
    let encoded = full_depth.encode();
    assert_eq!(Acceptance::decode(encoded.clone()).unwrap(), full_depth);
    assert_eq!(encoded.len(), MAX_ACCEPTANCE_BYTES);
}

#[test]
fn successful_receipt_commit_survives_restart_and_advances_next_debit() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let operator = Wallet::from_seed("operator", 1);
        let payment_context_epoch = registered_context(&control).await;
        let payment_context = payment_context_epoch.payment().clone();
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
                    body: payment_head_response(payment_context_epoch.clone(), 100).encode(),
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
        assert_eq!(recovered.store.debits_since(0).unwrap(), 7);
        assert_eq!(recovered.receipt_count(), 1);
        recovered
            .pay(&context, &mut chain, operator_address, &[(1, 3)])
            .await
            .unwrap();
        drop(recovered);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.store.debits_since(0).unwrap(), 10);
        assert_eq!(recovered.receipt_count(), 2);
        operator_server.await.unwrap();
    });
}

/// A current native payout opening and coherent status complete without operator bookkeeping.
#[test]
fn finalized_claim_completes_without_operator_bookkeeping() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let result = operator.complete_close(25).unwrap();
        finalize(&control, &result).await;
        let (request, position, _) =
            settlement_withdrawal(&operator, &result, &withdrawals, &wallets()[0].public_key());

        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &request);
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            25
        );
        assert!(agent.pending_withdrawal_claim.is_none());
        assert!(
            chain
                .payout_status(&context, position)
                .await
                .unwrap()
                .interval
                .is_none()
        );
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_withdrawal_claim.is_none());
    });
}

#[test]
fn payout_discovery_refreshes_a_page_output_at_the_newer_finalized_head() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let first = operator.complete_close(25).unwrap();
        finalize(&control, &first).await;
        let (request, position, _) =
            settlement_withdrawal(&operator, &first, &withdrawals, &wallets()[0].public_key());

        register(&control, &mut operator).await;
        let successor = operator.complete_close(26).unwrap();
        assert!(successor.roots.withdrawal_outputs.operations > position);
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let query = listener.local_addr().unwrap();
        let source = control.clone();
        context
            .child("finalize_between_payout_page_and_status")
            .spawn(move |context| async move {
                let mut advanced = false;
                loop {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    if !advanced
                        && request.method == METHOD_READ
                        && matches!(
                            ReadRequest::decode(request.body.clone()),
                            Ok(ReadRequest {
                                lookup: Lookup::Unclaimed { index },
                                ..
                            }) if index == position
                        )
                    {
                        finalize(&source, &successor).await;
                        advanced = true;
                    }
                    let response = rpc::call(&context, CHAIN, &request).await.unwrap();
                    rpc::send_response(&mut sink, &response).await.unwrap();
                }
            });

        let mut advancing = client_with_query_and_holders(&context, &control, query, CHAIN);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &request);
        let release = agent
            .claim_withdrawal(&context, &mut advancing, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(release.amount, 25);
        assert!(agent.pending_withdrawal_claim.is_none());
    });
}

/// Global payout positions remain distinct across finalized epochs and survive wallet restart.
#[test]
fn withdrawal_claim_positions_are_global_across_epochs() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let account = wallets()[0].public_key();

        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let first_withdrawals = operator.registration_boundary().unwrap().1;
        let first = operator.complete_close(41).unwrap();
        finalize(&control, &first).await;
        let (first_request, first_position, _) =
            settlement_withdrawal(&operator, &first, &first_withdrawals, &account);
        let second_recovery = operator.withdrawal_opening(&account).unwrap();

        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(20).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let second_withdrawals = operator.registration_boundary().unwrap().1;
        let second = operator.complete_close(42).unwrap();
        finalize(&control, &second).await;
        let (second_request, second_position, _) =
            settlement_withdrawal(&operator, &second, &second_withdrawals, &account);
        assert!(first_position < second_position);
        assert!(
            second_position < 128,
            "both outputs must share one discovery page"
        );
        let native_chain_id = chain.genesis().native.chain_id();
        let native_before = chain
            .native_balance(&context, native_chain_id, account.clone())
            .await
            .unwrap();

        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &first_request);
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            25
        );
        assert_eq!(
            chain
                .native_balance(&context, native_chain_id, account.clone())
                .await
                .unwrap(),
            native_before + 25
        );
        let height = control.advance(0).await;
        if height < first_request.body().deadline() {
            control
                .advance(first_request.body().deadline() - height)
                .await;
        }
        agent
            .observe_withdrawal_expiry(&context, &mut chain)
            .await
            .unwrap();
        assert!(agent.pending_withdrawal.is_none());
        drop(agent);

        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            second_recovery.root.digest,
            *second_request.body().state_root()
        );
        stage_withdrawal_intent_at(&mut agent, &second_request, second_recovery.opening);
        assert!(
            chain
                .payout_status(&context, first_position)
                .await
                .unwrap()
                .interval
                .is_none()
        );
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            20
        );
        assert_eq!(
            chain
                .native_balance(&context, native_chain_id, account)
                .await
                .unwrap(),
            native_before + 45
        );
        for position in [first_position, second_position] {
            assert!(
                chain
                    .payout_status(&context, position)
                    .await
                    .unwrap()
                    .interval
                    .is_none()
            );
        }
    });
}

#[test]
fn advisory_withdrawal_substitution_cannot_poison_the_pending_request() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent
            .balance(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        let action = WithdrawalAction::Amount(NonZeroU64::new(25).unwrap());
        let WithdrawalOutcome::Signed { request: first, .. } = agent
            .withdraw(&context, &mut chain, UNREACHABLE, action)
            .await
            .unwrap()
        else {
            panic!("unavailable operator acknowledged withdrawal");
        };

        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator.apply_withdrawal(first.clone(), false).unwrap();
        register(&control, &mut operator).await;
        let first_withdrawals = operator.registration_boundary().unwrap().1;
        let first_close = operator.complete_close(27).unwrap();
        finalize(&control, &first_close).await;
        let (_, first_position, first_claim) = settlement_withdrawal(
            &operator,
            &first_close,
            &first_withdrawals,
            &agent.account(),
        );

        operator.withdraw(0, action).unwrap();
        register(&control, &mut operator).await;
        let second_withdrawals = operator.registration_boundary().unwrap().1;
        let second_close = operator.complete_close(28).unwrap();
        finalize(&control, &second_close).await;
        let (second, second_position, second_claim) = settlement_withdrawal(
            &operator,
            &second_close,
            &second_withdrawals,
            &agent.account(),
        );
        assert_ne!(first, second);
        assert_eq!(first.body().destination(), second.body().destination());
        assert_eq!(first.body().action(), second.body().action());
        assert_eq!(first_claim.output(), second_claim.output());

        let mut selective = client_with_distinct_holders(&context, &control, 9_900);
        let mut refused = Vec::new();
        for holder in selective.holders().unwrap() {
            refused.push(payout_holder_refusing_position(&context, holder, first_position).await);
        }
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut selective, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            25
        );
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&first));
        assert!(agent.pending_withdrawal_claim.is_none());
        assert!(
            chain
                .payout_status(&context, second_position)
                .await
                .unwrap()
                .interval
                .is_none()
        );
        assert!(
            refused
                .iter()
                .all(|count| count.load(Ordering::Relaxed) == 1)
        );

        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            25
        );
        assert!(
            chain
                .payout_status(&context, first_position)
                .await
                .unwrap()
                .interval
                .is_none()
        );
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&first));
    });
}

#[test]
fn permissionless_spend_between_discovery_and_cache_preserves_the_wallet() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let close = operator.complete_close(29).unwrap();
        finalize(&control, &close).await;
        let (request, position, claim) =
            settlement_withdrawal(&operator, &close, &withdrawals, &wallets()[0].public_key());
        let status = chain.payout_status(&context, position).await.unwrap();
        let start = status.interval.unwrap().start;

        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &request);
        let query =
            consuming_payout_status_query(&context, control.clone(), position, start, claim).await;
        let mut racing = client_with_query_and_holders(&context, &control, query, CHAIN);
        let release = agent
            .claim_withdrawal(&context, &mut racing, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(release.amount, 25);
        assert!(agent.pending_withdrawal_claim.is_none());
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        assert!(
            chain
                .payout_status(&context, position)
                .await
                .unwrap()
                .interval
                .is_none()
        );
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        agent.ensure_store_usable().unwrap();
    });
}

#[test]
fn discovered_payout_is_durable_before_the_followup_status_read() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let close = operator.complete_close(29).unwrap();
        finalize(&control, &close).await;
        let (request, position, _) =
            settlement_withdrawal(&operator, &close, &withdrawals, &wallets()[0].public_key());

        let query = failing_second_payout_status_query(&context, position).await;
        let mut unavailable = client_with_query_and_holders(&context, &control, query, CHAIN);
        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &request);
        let error = agent
            .claim_withdrawal(&context, &mut unavailable, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("read coherent payout status"));
        assert_eq!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .unwrap()
                .claim
                .position(),
            position
        );
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            recovered
                .pending_withdrawal_claim
                .as_ref()
                .unwrap()
                .claim
                .position(),
            position
        );
    });
}

#[test]
fn cached_payout_rejects_a_recent_preissuance_head() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let before = chain.payout_checkpoint(&context).await.unwrap();
        let position = before.payouts.operations;
        let stale_request = ReadRequest::new(deployment(), Lookup::Unclaimed { index: position });
        let stale_response = control.read(stale_request.clone()).await;

        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let close = operator.complete_close(29).unwrap();
        finalize(&control, &close).await;
        let (_, issued_position, claim) =
            settlement_withdrawal(&operator, &close, &withdrawals, &wallets()[0].public_key());
        assert_eq!(issued_position, position);

        let candidate = PendingWithdrawalClaim {
            head: close.roots.withdrawal_outputs,
            claim,
        };
        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent.store.cache_withdrawal_claim(&candidate).unwrap();
        agent.pending_withdrawal_claim = Some(candidate);
        drop(agent);

        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 9_854)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let stale_request = stale_request.encode();
        let source = control.clone();
        let server = context
            .child("preissuance_payout_status")
            .spawn(move |_| async move {
                loop {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    let body = if request.body == stale_request {
                        stale_response.encode()
                    } else {
                        source
                            .read(ReadRequest::decode(request.body).unwrap())
                            .await
                            .encode()
                    };
                    rpc::send_response(&mut sink, &rpc::Response::Success { body })
                        .await
                        .unwrap();
                }
            });
        let mut stale = Client::new(
            control.identity(),
            deployment(),
            vec![address],
            context.child("preissuance_rng"),
        )
        .unwrap();
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .claim_withdrawal(&context, &mut stale, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("current payout head predates the cached candidate"),
            "{error:#}"
        );
        assert_eq!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .unwrap()
                .claim
                .position(),
            position
        );
        agent.ensure_store_usable().unwrap();
        server.abort();
    });
}

#[test]
fn spent_cached_payout_completes_after_head_advance_without_a_fresh_opening() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, UNREACHABLE);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let close = operator.complete_close(30).unwrap();
        finalize(&control, &close).await;
        let (_, position, claim) =
            settlement_withdrawal(&operator, &close, &withdrawals, &wallets()[0].public_key());
        let start = chain
            .payout_status(&context, position)
            .await
            .unwrap()
            .interval
            .unwrap()
            .start;

        let candidate = PendingWithdrawalClaim {
            head: close.roots.withdrawal_outputs,
            claim: claim.clone(),
        };
        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent.store.cache_withdrawal_claim(&candidate).unwrap();
        agent.pending_withdrawal_claim = Some(candidate);
        control
            .submit(SettlementTx::ClaimWithdrawal(WithdrawalClaimRequest {
                deployment: deployment(),
                start,
                claim,
            }))
            .await;
        assert!(
            chain
                .payout_status(&context, position)
                .await
                .unwrap()
                .interval
                .is_none()
        );

        register(&control, &mut operator).await;
        let successor = operator.complete_close(31).unwrap();
        finalize(&control, &successor).await;
        assert!(successor.roots.withdrawal_outputs.operations > position);
        drop(operator);

        let response = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(response.amount, 25);
        assert!(agent.pending_withdrawal_claim.is_none());
    });
}

#[test]
fn consumed_equal_output_cannot_complete_another_exact_request_after_retirement() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let account = wallets()[0].public_key();
        let initial = status(&control).await;
        let first = SignedWithdrawal::sign(
            deployment(),
            initial.state_root.digest,
            account.encode(),
            action,
            withdrawal_deadline(initial.height, &chain.genesis().timing()).unwrap(),
            wallets()[0].signer(),
        );
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator.apply_withdrawal(first.clone(), false).unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let source_close = operator.complete_close(29).unwrap();
        finalize(&control, &source_close).await;
        let (source_request, position, stale_claim) =
            settlement_withdrawal(&operator, &source_close, &withdrawals, &account);
        assert_eq!(source_request, first);

        let start = chain
            .payout_status(&context, position)
            .await
            .unwrap()
            .interval
            .unwrap()
            .start;
        control
            .submit(SettlementTx::ClaimWithdrawal(
                crate::chain::tx::WithdrawalClaimRequest {
                    deployment: deployment(),
                    start,
                    claim: stale_claim,
                },
            ))
            .await;
        assert!(
            chain
                .payout_status(&context, position)
                .await
                .unwrap()
                .interval
                .is_none()
        );

        // A cold wallet signs another request from the new state. The native output bytes would
        // be identical, but the saved authorization, root, and deadline are not.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent
            .balance(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed {
            request: second, ..
        } = agent
            .withdraw(&context, &mut chain, UNREACHABLE, action)
            .await
            .unwrap()
        else {
            panic!("unavailable operator acknowledged the second request");
        };
        assert_ne!(second, first);
        assert_eq!(second.body().destination(), first.body().destination());
        assert_eq!(second.body().action(), first.body().action());
        drop(agent);

        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let successor = operator.complete_close(30).unwrap();
        finalize(&control, &successor).await;
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        assert!(control.record(anchor_key(&deployment(), 0)).await.is_none());
        drop(operator);

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no unspent wallet-owned payout is available"),
            "{error:#}"
        );
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&second));
        assert!(agent.pending_withdrawal_claim.is_none());
        drop(agent);
        let reopened = Agent::open(database.path(), 0).unwrap();
        assert_eq!(reopened.pending_withdrawal.as_ref(), Some(&second));
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
        let chain_id = chain.genesis().native.chain_id();
        let native_before = chain
            .native_balance(&context, chain_id, agent.account())
            .await
            .unwrap();
        let mut dead = dead_client(&context);
        let error = agent.deposit(&context, &mut dead, 7).await.unwrap_err();
        assert!(format!("{error:#}").contains("record settlement deposit"));
        let event = agent.pending_deposit.clone().unwrap();
        control.submit(SettlementTx::Deposit(event.clone())).await;
        assert_eq!(
            chain.deposit(&context, event.event.id).await.unwrap(),
            Some(event.event.clone())
        );
        assert_eq!(
            chain
                .native_balance(&context, chain_id, agent.account())
                .await
                .unwrap(),
            native_before - 7
        );
        drop(agent);

        // The restarted wallet restores the exact staged event, so the retry replays
        // the recorded id even though its volatile nonce differs.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.pending_deposit.as_ref(), Some(&event));
        recovered.deposit_nonce = 41;
        let applied = recovered.deposit(&context, &mut chain, 7).await.unwrap();
        assert_eq!(applied, event.event);
        assert!(recovered.pending_deposit.is_none());
        assert_eq!(recovered.deposit_nonce, 42);
        drop(recovered);

        let reopened = Agent::open(database.path(), 0).unwrap();
        assert!(reopened.pending_deposit.is_none());
        assert_eq!(status(&control).await.custody, 407);
        assert_eq!(
            chain
                .native_balance(&context, chain_id, reopened.account())
                .await
                .unwrap(),
            native_before - 7
        );
    });
}

#[test]
fn unfunded_deposit_keeps_the_exact_staged_request() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;

        // Native funds cannot cover this deposit, so rejection leaves the signed
        // request available for retry after the account receives more funds.
        let amount = chain
            .native_balance(
                &context,
                chain.genesis().native.chain_id(),
                wallets()[0].public_key(),
            )
            .await
            .unwrap()
            + 1;

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
        // so the staged event survives for an exact retry.
        let error = agent
            .deposit(&context, &mut chain, amount)
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("record settlement deposit"), "{message}");
        assert!(agent.pending_deposit.is_some());
        control.submit(SettlementTx::Deposit(staged.clone())).await;
        assert_eq!(
            control
                .record(deposit_key(&deployment(), &staged.event.id))
                .await,
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
fn unfinalized_payout_is_not_trusted_before_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let result = operator.complete_close(28).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;

        let account = wallets()[0].public_key();
        let (request, _, claim) = settlement_withdrawal(&operator, &result, &withdrawals, &account);
        let release = crate::chain::state::WithdrawalResponse {
            amount: claim.output().amount(),
            destination: claim.output().destination().clone(),
        };

        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &request);
        let error = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no withdrawal epoch is finalized"),
            "{error:#}"
        );
        assert!(agent.pending_withdrawal_claim.is_none());
        drop(agent);

        // Only finalization publishes the payout into the authoritative native MMR. A cold retry
        // discovers the output independently before caching its current payout identity.
        let deadline = result.context.epoch_context().challenge_deadline();
        let height = control.advance(0).await;
        if height <= deadline {
            control.advance(deadline - height + 1).await;
        }
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            recovered
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            release
        );
        assert!(recovered.pending_withdrawal_claim.is_none());
    });
}

#[test]
fn cached_evidence_claims_after_the_operator_vanishes() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let result = operator.complete_close(31).unwrap();
        finalize(&control, &result).await;

        let account = wallets()[0].public_key();
        let (request, position, claim) =
            settlement_withdrawal(&operator, &result, &withdrawals, &account);
        let release = crate::chain::state::WithdrawalResponse {
            amount: claim.output().amount(),
            destination: claim.output().destination().clone(),
        };

        // The reserve releases from the self-verified copy against the
        // certified batch, and the vanished operator's missing acknowledgement
        // holds nothing open.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut agent, &request);
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            release
        );
        assert!(agent.pending_withdrawal_claim.is_none());
        assert!(
            chain
                .payout_status(&context, position)
                .await
                .unwrap()
                .interval
                .is_none()
        );
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_withdrawal_claim.is_none());
    });
}

#[test]
fn activity_resolved_payment_recovers_after_hard_fault_frozen_at_its_head() {
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
        let frozen_root = result.roots.successor;
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
                    body: stale_response(stale.payment(), 7),
                }
            })
            .await;
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
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        let Some(release) = recovered
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap()
        else {
            panic!("expected a positive frozen balance")
        };
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
                operator.apply_withdrawal(request.request, false).unwrap();
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
        let (listener, mut operator) = applying.await.unwrap();

        // The true reserve finalizes in the real certified epoch-0 batch.
        register(&control, &mut operator).await;
        let withdrawals = operator.registration_boundary().unwrap().1;
        let result = operator.complete_close(35).unwrap();
        finalize(&control, &result).await;
        let (_, _, claim) = settlement_withdrawal(&operator, &result, &withdrawals, &account);
        let expected = crate::chain::state::WithdrawalResponse {
            amount: claim.output().amount(),
            destination: claim.output().destination().clone(),
        };
        drop(listener);
        drop(operator);

        let release = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(release, expected);
        assert_eq!(release.amount, 7);
        assert!(agent.pending_withdrawal_claim.is_none());
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

        // Its close is admitted but not finalized, so the exact request remains pending without
        // a finalized payout candidate.
        register(&control, &mut operator).await;
        let first_close = operator.complete_close(36).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&first_close)),
        )
        .await;
        let waiting = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(
            format!("{waiting:#}").contains("no withdrawal epoch is finalized"),
            "{waiting:#}"
        );
        assert!(agent.pending_withdrawal_claim.is_none());

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
        assert!(agent.pending_withdrawal_claim.is_none());
        assert!(agent.pending_withdrawal.is_some());

        // Finalization authenticates the first current payout opening and
        // unblocks the second withdrawal, and both reserves release against
        // their own certified batches.
        finalize(&control, &first_close).await;
        let first_withdrawals =
            WithdrawalBatch::new(vec![agent.pending_withdrawal.as_ref().unwrap().clone()]).unwrap();
        let (_, _, claim) =
            settlement_withdrawal(&operator, &first_close, &first_withdrawals, &account);
        let first_expected = crate::chain::state::WithdrawalResponse {
            amount: claim.output().amount(),
            destination: claim.output().destination().clone(),
        };
        let first_release = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(first_release, first_expected);
        assert_eq!(first_release.amount, 7);
        assert!(agent.pending_withdrawal_claim.is_none());
        let height = control.advance(0).await;
        let deadline = agent.pending_withdrawal.as_ref().unwrap().body().deadline();
        if height < deadline {
            control.advance(deadline - height).await;
        }
        agent
            .observe_withdrawal_expiry(&context, &mut chain)
            .await
            .unwrap();
        assert!(agent.pending_withdrawal.is_none());
        let applying_second = context.child("applying_second").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
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
        let (listener, mut operator) = applying_second.await.unwrap();

        // The second close finalizes before the wallet fetches its evidence. Configured native
        // custodians retain the source and current proof for later claims.
        register(&control, &mut operator).await;
        let second_withdrawals = operator.registration_boundary().unwrap().1;
        let second_close = operator.complete_close(37).unwrap();
        finalize(&control, &second_close).await;
        let (_, _, claim) =
            settlement_withdrawal(&operator, &second_close, &second_withdrawals, &account);
        let second_expected = crate::chain::state::WithdrawalResponse {
            amount: claim.output().amount(),
            destination: claim.output().destination().clone(),
        };
        drop(listener);
        drop(operator);
        let second_release = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(second_release, second_expected);
        assert_eq!(second_release.amount, 5);
        assert!(agent.pending_withdrawal_claim.is_none());
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
        let payment_context_epoch = registered_context(&control).await;
        let head = payment_head_response(payment_context_epoch, 100);
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

        let mut recovered = Agent::open(database.path(), 0).unwrap();
        let Some(release) = recovered
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap()
        else {
            panic!("expected a positive frozen balance")
        };
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, 100);
    });
}

/// Registers the omitting boundary on the chain, builds the deterministic
/// omitting close at the chain-assigned deadlines (the admitted close credits
/// a deposit to a bystander and omits Bob, while Bob holds an operator-signed
/// receipt crediting him), and admits it, so its inclusive challenge window
/// is open until the assigned absolute deadline.
async fn admit_omitting(
    context: &deterministic::Context,
    control: &harness::Control,
) -> crate::protocol::OmittingClose {
    let (deposit, deposits) = crate::protocol::omitting_boundary().unwrap();
    applied(
        control,
        &SettlementTx::Deposit(signed_deposit(control, deposit)),
    )
    .await;
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let deposits_root = deposits.root::<Sha256>().unwrap();
    let withdrawals = WithdrawalBatch::empty();
    let signature =
        protocol.sign_chain_registration(0, 400, &deposits_root, &withdrawals, epoch_fee(control));
    applied(
        control,
        &SettlementTx::RegisterEpoch(RegisterEpochRequest {
            fee: epoch_fee(control),
            deployment: deployment(),
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,

            withdrawals,
            openings: Vec::new(),
            signature,
        }),
    )
    .await;
    let record = registration_record(control).await;
    let state = crate::protocol::init_replica(
        context.child("omitting_state"),
        "omitting",
        commonware_parallel::Rayon::new(NonZeroUsize::MIN).unwrap(),
        crate::protocol::genesis_balances(&crate::protocol::deployments()[0]).unwrap(),
    )
    .await
    .unwrap();
    let fixture = Box::pin(crate::protocol::omitting_close(
        state,
        &mut TestRng::new(7),
        record.admission_deadline,
        record.challenge_deadline,
    ))
    .await
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
    let deadline = fixture.result.context.epoch_context().challenge_deadline();
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
        fixture.result.context.payment(),
        payer,
        &wallets()[1].public_key(),
        5,
    )
}

/// A second paying edge whose payer key sorts after Alice's, so reconciliation assesses
/// the fixture's Alice edge first. It stays in Alice's native row-absence interval, so the same
/// authenticated adjacent rows prove that both payers were omitted.
fn later_payer() -> Wallet {
    let alice = wallets()[0].public_key();
    let bystander = wallets()[2].public_key();
    (2_000..3_000)
        .map(|seed| Wallet::from_seed("later-payer", seed))
        .find(|wallet| {
            let key = wallet.public_key();
            key > alice && (key < bystander) == (alice < bystander)
        })
        .expect("a seeded key sorts after Alice in the same absence interval")
}

/// (c) THE POINT: a receiver holding a verified receipt convicts a close that omits its
/// credit, end to end through a real challenge transaction whose proven verdict is read
/// back certified, and the close is invalidated. With the validators dead, the
/// operator's own served lookup is what convicts it.
#[test]
fn omitted_credit_is_convicted_by_the_held_receipt() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, UNREACHABLE);
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let bob_receipt = fixture.held_receipt.clone();
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
                    body: bob_lookup.encode(),
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
        assert!(summary.protected.is_empty());

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
            ))) if proven == fixture.result.header.batch_id::<Sha256>()
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
        let receipt_id = Sha256::hash(&[receipt.ack.body().encode().as_ref()]);

        // The chain registered a different anchor for epoch 0 than the operator's forgery.
        let registered_epoch = registered_context(&control).await;
        let registered = registered_epoch.payment().clone();
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
        assert!(!bob.has_receipt(&payer, &receipt_id).unwrap());
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
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
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
                    body: lookup.encode(),
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
        assert!(summary.protected.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert!(chain.status(&context).await.unwrap().hard_faulted);
        operator_server.await.unwrap();
    });
}

#[test]
fn mixed_edge_refusal_does_not_shadow_live_challenge() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, UNREACHABLE);
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let alice_edge = fixture.held_receipt.clone();
        let later = later_payer();
        let later_key = later.public_key();
        let later_edge = held_from(&fixture, &later);
        let later_lookup = fixture.held_lookup.clone();
        later_lookup
            .resolve::<Sha256>(
                &activity_range(&fixture.result),
                &later_key,
                &wallets()[1].public_key(),
            )
            .unwrap();

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
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::CommittedEntry(request) = request else {
                    panic!("expected a committed entry request");
                };
                assert_eq!(request.payer, wallets()[0].public_key());
                rpc::Response::Error {
                    error: Bytes::from_static(b"first payer unavailable"),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                let operator_rpc::OperatorRequest::CommittedEntry(request) = request else {
                    panic!("expected a committed entry request");
                };
                assert_eq!(request.payer, later_key);
                rpc::Response::Success {
                    body: later_lookup.encode(),
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
        assert_eq!(summary.convicted, [0]);
        assert!(summary.withheld.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert!(chain.status(&context).await.unwrap().hard_faulted);
        operator_server.await.unwrap();
    });
}

#[test]
fn mixed_edge_refusal_does_not_hide_finalized_understatement() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let alice_edge = fixture.held_receipt.clone();
        let later = later_payer();
        let later_key = later.public_key();
        let later_edge = held_from(&fixture, &later);
        let holder = selective_source_holder(&context, 0, 0, Some(later_key)).await;
        let mut chain = client_with_holders(&context, &control, holder);

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
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        finalize_omitting(&control, &fixture).await;
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.unenforceable, [0]);
        assert!(summary.withheld.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
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
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let bob_receipt = fixture.held_receipt.clone();
        let range = activity_range(&fixture.result);

        // A lookup built against another close's root: it decodes and is served under the
        // anchored batch and root, but it cannot resolve against this close's change root.
        let mut foreign = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        foreign.pay(0, 1, 5).unwrap();
        foreign.complete_close(41).unwrap();
        let foreign_lookup = foreign
            .committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0)
            .unwrap();
        assert!(
            foreign_lookup
                .resolve::<Sha256>(
                    &range,
                    &wallets()[0].public_key(),
                    &wallets()[1].public_key(),
                )
                .is_err()
        );
        let poison_body = foreign_lookup.encode();
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
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let bob_receipt = fixture.held_receipt.clone();

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
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().total, 5);
        assert_eq!(bob.store.credits_since(0).unwrap(), 5);
        finalize_omitting(&control, &fixture).await;
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();

        // The dead end is loud and terminal: recorded, surfaced, and never reconciled.
        assert_eq!(summary.unenforceable, [0]);
        assert!(
            summary.reconciled.is_empty()
                && summary.convicted.is_empty()
                && summary.protected.is_empty()
        );
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert_eq!(bob.last_reconciled_epoch(), None);
        operator_server.await.unwrap();
    });
}

/// A finalized close whose committed evidence the operator withholds is an alarm, not a silent
/// retry while its descriptor remains retained: conviction is no longer possible and coverage
/// cannot be verified, so the dead end is surfaced once per stretch of withholding and it
/// self-heals into a terminal verdict if the evidence is eventually served.
#[test]
fn withheld_evidence_past_finalization_alarms_once() {
    deterministic::Runner::default().start(|context| async move {
        let (control, _) = chain(&context).await;
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let bob_receipt = fixture.held_receipt.clone();
        let holder =
            selective_source_holder(&context, 0, control.identity().validators.len() * 2, None)
                .await;
        let mut chain = client_with_holders(&context, &control, holder);

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
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().total, 5);
        assert_eq!(bob.store.credits_since(0).unwrap(), 5);
        finalize_omitting(&control, &fixture).await;

        // The first withheld pass alarms, the second is latched, and the epoch keeps retrying.
        let first = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(first.withheld, [0]);
        assert!(
            first.reconciled.is_empty() && first.convicted.is_empty() && first.protected.is_empty()
        );
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

#[test]
fn successor_finality_withholds_retired_receipts_without_requerying_evidence() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let holder = SocketAddr::from(([127, 0, 0, 1], 9_706));
        let evidence_reads = garbage_holder(
            &context,
            holder,
            rpc::error_response("retired evidence must not be queried".into()),
        )
        .await;
        let (query, retired_reads) = query_counting_retired_evidence(&context).await;
        let mut chain = client_with_query_and_holders(&context, &control, query, holder);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let payment = register(&control, &mut operator).await;
        let receipt = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 5);

        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let server = context
            .child("retired_receipt_intake")
            .spawn(move |_| async move {
                respond(&mut listener, |request| {
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
        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(bob.incoming().total, 5);

        operator.pay(2, 3, 1).unwrap();
        let first = operator.complete_close(60).unwrap();
        finalize(&control, &first).await;
        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let successor = operator.complete_close(61).unwrap();
        finalize(&control, &successor).await;
        assert_eq!(status(&control).await.last_finalized, Some(1));

        let before_evidence = evidence_reads.load(Ordering::Relaxed);
        let before_retired = retired_reads.load(Ordering::Relaxed);
        let summary = bob
            .reconcile(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(summary.withheld, [0]);
        assert_eq!(evidence_reads.load(Ordering::Relaxed), before_evidence);
        assert_eq!(retired_reads.load(Ordering::Relaxed), before_retired);
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);
        assert!(
            bob.reconcile(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(evidence_reads.load(Ordering::Relaxed), before_evidence);
        assert_eq!(retired_reads.load(Ordering::Relaxed), before_retired);

        drop(bob);
        let mut recovered = Agent::open(database.path(), 1).unwrap();
        assert_eq!(
            recovered
                .reconcile(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .withheld,
            [0]
        );
        assert_eq!(evidence_reads.load(Ordering::Relaxed), before_evidence);
        assert_eq!(retired_reads.load(Ordering::Relaxed), before_retired);
        assert_eq!(recovered.store.unreconciled_incoming_epochs().unwrap(), [0]);
    });
}

/// (a) Happy path: pairs are fetched incrementally, verified, persisted, survive restart,
/// and the certifiably finalized epoch reconciles cleanly and is durably marked. A
/// longer-retention native holder serves the authenticated source and activity opening.
#[test]
fn verified_incoming_reconciles_and_survives_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let holder = source_holder(&context).await;
        let mut chain = client_with_holders(&context, &control, holder);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        operator.pay(0, 1, 3).unwrap();
        let result = operator.complete_close(44).unwrap();
        finalize(&control, &result).await;

        // The reconstructed committed-side evidence matches the finalized roots, so the
        // certified anchor below names the exact close the operator serves lookups for.
        let evidence = operator
            .committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0)
            .unwrap();
        assert_eq!(
            evidence
                .resolve::<Sha256>(
                    &activity_range(&result),
                    &wallets()[0].public_key(),
                    &wallets()[1].public_key(),
                )
                .unwrap(),
            (8, 2)
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
            operator
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

        // A successor retires the descriptor only after the clean outcome is durable.
        let mut operator = operator_server.await.unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 2, 1).unwrap();
        let successor = operator.complete_close(45).unwrap();
        finalize(&control, &successor).await;

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
    });
}

#[test]
fn late_incoming_page_reopens_a_clean_reconciliation() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        operator.pay(0, 1, 3).unwrap();
        let rows = operator
            .incoming_payments(&wallets()[1].public_key(), 0, 10)
            .unwrap();
        let result = operator.complete_close(1).unwrap();
        finalize(&control, &result).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context.child("paged_receipts").spawn(move |_| async move {
            for _ in 0..2 {
                respond(&mut listener, |request| match request {
                    operator_rpc::OperatorRequest::IncomingPayments(request) => {
                        let row = rows
                            .iter()
                            .find(|row| row.sequence > request.cursor)
                            .unwrap();
                        rpc::Response::Success {
                            body: incoming_response(&[(row.receipt.clone(), row.sequence)])
                                .encode(),
                        }
                    }
                    request => operator_rpc::handle_decoded(&mut operator, request),
                })
                .await;
            }
        });
        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().total, 5);
        assert_eq!(
            bob.reconcile(&context, &mut chain, address)
                .await
                .unwrap()
                .reconciled,
            [0]
        );
        assert_eq!(bob.last_reconciled_epoch(), Some(0));
        bob.intake_incoming(&context, &mut chain, address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().total, 8);
        assert_eq!(bob.last_reconciled_epoch(), None);
        drop(bob);
        let mut bob = Agent::open(database.path(), 1).unwrap();
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);
        assert_eq!(
            bob.reconcile(&context, &mut chain, address)
                .await
                .unwrap()
                .reconciled,
            [0]
        );
        server.await.unwrap();
    });
}

#[test]
fn retired_descriptor_skips_first_time_receipt_without_credit() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let holder =
            selective_source_holder(&context, 1, control.identity().validators.len(), None).await;
        let mut chain = client_with_holders(&context, &control, holder);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();

        // Operational balance versions are pruned while authenticated close evidence remains.
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let held = operator.complete_close(50).unwrap();
        finalize(&control, &held).await;
        for epoch in 1..=5 {
            register(&control, &mut operator).await;
            operator.pay(0, 2, 1).unwrap();
            let result = operator.complete_close(50 + epoch).unwrap();
            assert_eq!(result.context.payment().epoch(), epoch);
            finalize(&control, &result).await;
        }
        assert_eq!(status(&control).await.last_finalized, Some(5));
        assert!(
            operator
                .committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0)
                .is_ok()
        );

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            relay(&mut operator_listener, &mut operator).await;
        });

        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(
            bob.incoming(),
            IncomingSummary {
                total: 0,
                count: 0,
                cursor: 1
            }
        );
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert!(summary.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        drop(bob);
        let mut bob = Agent::open(database.path(), 1).unwrap();
        let summary = bob
            .reconcile(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert!(summary.is_empty());
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
        let anchor_request = crate::chain::query::ReadRequest::new(
            deployment(),
            crate::chain::query::Lookup::Anchor { epoch: 0 },
        );
        let before_registration = control.read(anchor_request.clone()).await;
        let mut query_listener = context.bind(SocketAddr::from(([127, 0, 0, 1], 3))).await.unwrap();
        let query_address = query_listener.local_addr().unwrap();
        let lagging_query = context.child("lagging_anchor").spawn(move |_| async move {
            respond_rpc(&mut query_listener, |request| {
                assert_eq!(request.method, crate::chain::query::METHOD_READ);
                assert_eq!(request.body, anchor_request.encode());
                rpc::Response::Success { body: before_registration.encode() }
            }).await;
        });
        let mut lagging = Client::new(control.identity(), deployment(), vec![query_address], context.child("lagging_rng")).unwrap();

        // The receipt binds the certifiably registered epoch-0 context, so intake
        // anchors it against the chain's own registration record.
        let registered_epoch = registered_context(&control).await;
        let registered = registered_epoch.payment().clone();
        let alice = &wallets()[0];
        let bob = wallets()[1].public_key();
        let receipt = issued_receipt(&registered, alice, &bob, 5);
        let receipt_id = Sha256::hash(&[receipt.ack.body().encode().as_ref()]);

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let served = receipt.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // A delayed registration and a repeated page must both preserve the held receipt.
            for cursor in [0, 0, 1] {
                let served = served.clone();
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::IncomingPayments(request) if request.cursor == cursor));
                    rpc::Response::Success {
                        body: if cursor == 0 {
                            incoming_response(&[(served, 1)])
                        } else {
                            operator_rpc::IncomingPaymentsResponse {
                                next_cursor: cursor,
                                pairs: Vec::new(),
                            }
                        }
                        .encode(),
                    }
                })
                .await;
            }
        });

        let mut bob = Agent::open(database.path(), 1).unwrap();
        assert!(bob.intake_incoming(&context, &mut lagging, operator_address).await.is_err());
        assert_eq!(bob.incoming().cursor, 0);
        assert_eq!(bob.incoming().count, 0);
        lagging_query.await.unwrap();
        drop(bob);
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
        assert!(recovered.has_receipt(&alice.public_key(), &receipt_id).unwrap());

        // Fetching after the held page returns empty and leaves the ledger unchanged.
        recovered
            .intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(recovered.incoming().count, 1);
        assert_eq!(recovered.incoming().total, 5);
        operator_server.await.unwrap();
    });
}

#[test]
fn incoming_page_validation_preserves_later_honest_progress() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let registered = registered_context(&control).await;
        let payment = registered.payment().clone();
        let receiver = wallets()[1].public_key();
        let first_payer = wallets().remove(0);
        let second_payer = wallets().remove(2);
        let first = issued_receipt(&payment, &first_payer, &receiver, 5);
        let second = issued_receipt(&payment, &second_payer, &receiver, 7);
        let first_id = Sha256::hash(&[first.ack.body().encode().as_ref()]);
        let second_id = Sha256::hash(&[second.ack.body().encode().as_ref()]);

        let mut cursor_mismatch = incoming_response(&[(first.clone(), 1)]);
        cursor_mismatch.next_cursor = 3;
        let malformed = [
            (cursor_mismatch, "does not match its last sequence"),
            (
                incoming_response(&[(first.clone(), 1), (second.clone(), 1)]),
                "not strictly increasing",
            ),
            (
                incoming_response(&[(first.clone(), 2), (second.clone(), 1)]),
                "not strictly increasing",
            ),
            (
                incoming_response(&[(first.clone(), u64::MAX)]),
                "incoming cursor exceeds SQLite INTEGER range",
            ),
        ];
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let canonical_first = first.clone();
        let canonical_second = second.clone();
        let served_malformed = malformed.clone();
        let server = context.child("incoming_pages").spawn(move |_| async move {
            for (page, _) in served_malformed {
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::IncomingPayments(request) if request.cursor == 0));
                    rpc::Response::Success {
                        body: page.encode(),
                    }
                })
                .await;
            }
            respond(&mut operator_listener, move |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::IncomingPayments(request) if request.cursor == 0));
                rpc::Response::Success {
                    body: incoming_response(&[(canonical_first, 2), (canonical_second, 3)])
                        .encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 1).unwrap();
        for (_, expected) in malformed {
            let error = agent
                .intake_incoming(&context, &mut chain, operator_address)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains(expected));
            assert_eq!(agent.incoming(), IncomingSummary::default());
            agent.ensure_store_usable().unwrap();
        }
        drop(agent);

        let mut agent = Agent::open(database.path(), 1).unwrap();
        agent
            .intake_incoming(&context, &mut chain, operator_address)
            .await
            .unwrap();
        assert_eq!(
            agent.incoming(),
            IncomingSummary {
                total: 12,
                count: 2,
                cursor: 3,
            }
        );
        assert!(agent.has_receipt(&first_payer.public_key(), &first_id).unwrap());
        assert!(agent.has_receipt(&second_payer.public_key(), &second_id).unwrap());
        server.await.unwrap();
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

        // Escalation retains the exact request for retry without fabricating a payout candidate
        // before a finalized output exists.
        assert!(agent.pending_withdrawal_claim.is_none());
        drop(agent);
        let reopened = Agent::open(database.path(), 0).unwrap();
        assert!(reopened.pending_withdrawal_claim.is_none());
        assert_eq!(reopened.pending_withdrawal.as_ref(), Some(&request));
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

        // The reopened payer retains its empty receiver ledger.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.incoming(), IncomingSummary::default());
        assert_eq!(recovered.last_reconciled_epoch(), None);
    });
}

/// With the operator unreachable, the balance poll and the withdrawal open the
/// wallet's leaf through its validators, verified against the certified
/// head. Before any close finalizes that is the genesis state. After one
/// finalizes, the holders have released its dealing, and the same root is
/// opened from the admitted successor's predecessor state instead.
#[test]
fn head_and_withdrawal_use_validators_with_operator_unreachable() {
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
        operator.apply_withdrawal(request, true).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let result = operator.complete_close(60).unwrap();
        finalize(&control, &result).await;
        assert_eq!(
            agent
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            INITIAL_BALANCE - 7 - 5
        );

        // Finalized balance evidence remains available when another close is admitted.
        register(&control, &mut operator).await;
        operator.pay(1, 2, 1).unwrap();
        let successor = operator.complete_close(61).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&successor)),
        )
        .await;
        let finalized_root = status(&control).await.state_root;
        assert_eq!(finalized_root, result.roots.successor);
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
/// validators' committed entry, which the chain proves. The operator is not
/// on the enforcement path at all.
#[test]
fn reconcile_convicts_with_validator_served_lookup_while_operator_withholds() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
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
        assert!(summary.protected.is_empty());
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

#[test]
fn ui_assurance_survives_slow_display_and_evidence() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, _) = chain(&context).await;
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        let batch_id = admitted_batch(&fixture);
        let receipt = fixture.held_receipt.clone();
        let mut listener = context.bind(SocketAddr::from(([127, 0, 0, 1], 2))).await.unwrap();
        let operator = listener.local_addr().unwrap();
        context.child("slow_operator").spawn(move |context| async move {
            loop {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let Ok(request) = rpc::recv_request(&mut stream).await else { continue; };
                context.sleep(Duration::from_millis(250)).await;
                let response = if request.method == operator_rpc::METHOD_INCOMING_PAYMENTS {
                    rpc::Response::Success { body: incoming_response(&[(receipt.clone(), 1)]).encode() }
                } else {
                    rpc::error_response("unavailable".into())
                };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
        let mut bob = Agent::open(database.path(), 1).unwrap();
        let holder = SocketAddr::from(([127, 0, 0, 1], 9_700));
        let served = forwarding_holder(&context, holder, Duration::from_millis(250)).await;
        let mut chain = client_with_holders(&context, &control, holder);
        let started = context.current();
        crate::ui::run_with_io(&context, operator, &mut chain, &mut bob,
            |_, _| Ok(()),
            || Ok((context.current().duration_since(started).unwrap() >= Duration::from_secs(3))
                .then(|| crossterm::event::KeyEvent::new(crossterm::event::KeyCode::Char('q'), crossterm::event::KeyModifiers::NONE))),
        ).await.unwrap();
        assert!(matches!(control.record(fault_key(&deployment())).await,
            Some(Record::Fault(FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge {
                batch_id: proven, kind: commonware_clearing::bajillion::challenge::ChallengeKind::HigherAckEntry,
            }))) if proven == batch_id));
        assert!(served.load(Ordering::Relaxed) > 0);
        assert_eq!(chain.status(&context).await.unwrap().last_finalized, None);
        drop(bob);
        let bob = Agent::open(database.path(), 1).unwrap();
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
    });
}

#[test]
fn ui_quits_while_assurance_is_waiting() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let epoch = registered_context(&control).await;
        let mut alice = Agent::new(0).unwrap();
        let receipt = issued_receipt(epoch.payment(), &wallets()[1], &alice.account(), 5);
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let server = context.child("receipt").spawn(move |_| async move {
            respond(&mut listener, |_| rpc::Response::Success {
                body: incoming_response(&[(receipt, 1)]).encode(),
            })
            .await;
            listener
        });
        alice
            .intake_incoming(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        let listener = server.await.unwrap();
        chain = Client::new(
            chain.genesis(),
            deployment(),
            vec![UNREACHABLE],
            context.child("waiting_client"),
        )
        .unwrap();
        let started = context.current();
        let mut polls = 0;
        crate::ui::run_with_io(
            &context,
            UNREACHABLE,
            &mut chain,
            &mut alice,
            |_, _| Ok(()),
            || {
                polls += 1;
                Ok(Some(crossterm::event::KeyEvent::new(
                    crossterm::event::KeyCode::Char(if polls == 1 { 'p' } else { 'q' }),
                    crossterm::event::KeyModifiers::NONE,
                )))
            },
        )
        .await
        .unwrap();
        assert!(context.current().duration_since(started).unwrap() <= Duration::from_millis(250));
        assert!(alice.pending_payment.is_none());
        drop(listener);
    });
}

/// An admitted-only claim attempt retains the retry authorization; after finality the native
/// payout MMR authenticates and caches the wallet-owned candidate without the operator.
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
        let withdrawals = operator.registration_boundary().unwrap().1;
        let result = operator.complete_close(71).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        let (exact_request, _, _) =
            settlement_withdrawal(&operator, &result, &withdrawals, &wallets()[0].public_key());

        // An admitted-only close has not published an authoritative payout candidate.
        let mut alice = Agent::open(database.path(), 0).unwrap();
        stage_withdrawal_intent(&mut alice, &exact_request);
        let waiting = alice
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(
            format!("{waiting:#}").contains("no withdrawal epoch is finalized"),
            "{waiting:#}"
        );
        assert!(alice.pending_withdrawal_claim.is_none());
        drop(alice);

        // After finalization the restarted wallet authenticates the native payout.
        finalize(&control, &result).await;
        let mut alice = Agent::open(database.path(), 0).unwrap();
        assert!(alice.pending_withdrawal_claim.is_none());
        let release = alice
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(release.amount, 25);
        assert!(alice.pending_withdrawal_claim.is_none());
        // A fresh wallet cannot complete another intent with the already consumed output.
        let mut late = Agent::new(0).unwrap();
        let error = late
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("no unspent wallet-owned payout is available"));
    });
}

#[test]
fn finalized_zero_withdrawal_completes_without_an_asset_release() {
    for other_reserve in [false, true] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut alice = Agent::open(database.path(), 0).unwrap();
            alice
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap();
            let WithdrawalOutcome::Signed { request, .. } = alice
                .withdraw(&context, &mut chain, UNREACHABLE, WithdrawalAction::Close)
                .await
                .unwrap()
            else {
                panic!("unavailable operator acknowledged the request")
            };
            operator.apply_withdrawal(request.clone(), false).unwrap();
            if other_reserve {
                operator
                    .withdraw(2, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
                    .unwrap();
            }
            register(&control, &mut operator).await;
            operator.pay(0, 1, 100).unwrap();
            let withdrawals = operator.registration_boundary().unwrap().1;
            let result = operator.complete_close(1).unwrap();
            assert_eq!(result.withdrawal_total, if other_reserve { 25 } else { 0 });
            let (_, position, _) =
                settlement_withdrawal(&operator, &result, &withdrawals, &alice.account());
            let receiver_source = other_reserve.then(|| {
                settlement_withdrawal(&operator, &result, &withdrawals, &wallets()[2].public_key())
            });
            applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
            assert!(
                alice
                    .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                    .await
                    .is_err()
            );
            assert!(alice.pending_withdrawal_claim.is_none());
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            finalize(&control, &result).await;
            drop(operator);
            if other_reserve {
                let mut receiver = Agent::new(2).unwrap();
                let (request, _, claim) = receiver_source.unwrap();
                stage_withdrawal_intent(&mut receiver, &request);
                let candidate = PendingWithdrawalClaim {
                    head: result.roots.withdrawal_outputs,
                    claim,
                };
                receiver.store.cache_withdrawal_claim(&candidate).unwrap();
                receiver.pending_withdrawal_claim = Some(candidate);
                assert_eq!(
                    receiver
                        .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                        .await
                        .unwrap()
                        .amount,
                    25
                );
            }
            assert_eq!(chain.status(&context).await.unwrap().claimable, 0);
            drop(alice);
            let mut alice = Agent::open(database.path(), 0).unwrap();
            let result = alice
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap();
            assert_eq!(result.amount, 0);
            assert_eq!(result.destination.as_ref(), alice.account().as_ref());
            assert!(
                chain
                    .payout_status(&context, position)
                    .await
                    .unwrap()
                    .interval
                    .is_none()
            );
            drop(alice);
            let alice = Agent::open(database.path(), 0).unwrap();
            assert!(alice.pending_withdrawal_claim.is_none());
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
        });
    }
}

#[test]
fn scripted_restart_submits_an_uncarried_withdrawal() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent
            .balance(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed {
            request: original, ..
        } = agent
            .withdraw(
                &context,
                &mut chain,
                UNREACHABLE,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap()
        else {
            panic!("undelivered request");
        };
        drop(agent);
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let served_control = control.clone();
        let expected = original.clone();
        let server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::ApplyWithdrawal(apply) = &request else {
                    panic!("expected exact withdrawal retry")
                };
                assert_eq!(apply.request, expected);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            register(&served_control, &mut operator).await;
            let close = operator.complete_close(1).unwrap();
            finalize(&served_control, &close).await;
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let WithdrawalOutcome::Applied { request, .. } = agent
            .withdraw(
                &context,
                &mut chain,
                UNREACHABLE,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap()
        else {
            panic!("exact restart retry was not acknowledged")
        };
        assert_eq!(request, original);
        server.await.unwrap();
        assert_eq!(
            agent
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            7
        );
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&original));
        assert!(agent.pending_withdrawal_claim.is_none());
        assert_eq!(status(&control).await.claimable, 0);
    });
}

#[test]
fn uncached_finalized_payouts_require_an_unspent_candidate() {
    for (already_released, escalated, acknowledged) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (false, false, true),
        (true, false, true),
        (false, true, true),
        (true, true, true),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let alice_database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut alice = Agent::open(alice_database.path(), 0).unwrap();
            alice
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap();
            let WithdrawalOutcome::Signed { request, .. } = alice
                .withdraw(
                    &context,
                    &mut chain,
                    UNREACHABLE,
                    WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()),
                )
                .await
                .unwrap()
            else {
                panic!("unavailable operator acknowledged the withdrawal");
            };
            if escalated {
                assert_eq!(
                    alice
                        .escalate_withdrawal(&context, &mut chain)
                        .await
                        .unwrap(),
                    request
                );
            }
            let staged = operator
                .apply_withdrawal(request.clone(), escalated)
                .unwrap();
            let ack = operator_rpc::WithdrawalAck {
                epoch: staged.epoch,
                digest: operator_rpc::withdrawal_digest(&request),
            };
            if acknowledged {
                let mut listener = context
                    .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                    .await
                    .unwrap();
                let address = listener.local_addr().unwrap();
                let expected = request.clone();
                let server = context
                    .child("acknowledged_withdrawal")
                    .spawn(move |_| async move {
                        respond(&mut listener, |message| {
                            let operator_rpc::OperatorRequest::ApplyWithdrawal(message) = message
                            else {
                                panic!("expected exact withdrawal retry");
                            };
                            assert_eq!(message.request, expected);
                            rpc::Response::Success { body: ack.encode() }
                        })
                        .await;
                    });
                let WithdrawalOutcome::Applied {
                    request: retried, ..
                } = alice
                    .withdraw(&context, &mut chain, address, *request.body().action())
                    .await
                    .unwrap()
                else {
                    panic!("matching withdrawal was not acknowledged");
                };
                assert_eq!(retried, request);
                server.await.unwrap();
            }
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            drop(alice);
            register(&control, &mut operator).await;
            operator.pay(1, operator.wallet_count(), 40).unwrap();
            let withdrawals = operator.registration_boundary().unwrap().1;
            let first = operator.complete_close(1).unwrap();
            finalize(&control, &first).await;
            let (source_request, _, source_claim) =
                settlement_withdrawal(&operator, &first, &withdrawals, &wallets()[0].public_key());
            assert_eq!(source_request, request);
            let native_chain_id = chain.genesis().native.chain_id();
            let native_before = chain
                .native_balance(&context, native_chain_id, wallets()[0].public_key())
                .await
                .unwrap();
            if already_released {
                let position = source_claim.position();
                let start = chain
                    .payout_status(&context, position)
                    .await
                    .unwrap()
                    .interval
                    .unwrap()
                    .start;
                control
                    .submit(SettlementTx::ClaimWithdrawal(
                        crate::chain::tx::WithdrawalClaimRequest {
                            deployment: deployment(),
                            start,
                            claim: source_claim.clone(),
                        },
                    ))
                    .await;
                assert!(
                    chain
                        .payout_status(&context, position)
                        .await
                        .unwrap()
                        .interval
                        .is_none()
                );
                assert_eq!(
                    chain
                        .native_balance(&context, native_chain_id, wallets()[0].public_key())
                        .await
                        .unwrap(),
                    native_before + 25
                );
            }
            register(&control, &mut operator).await;
            operator.pay(2, operator.wallet_count(), 20).unwrap();
            let second = operator.complete_close(2).unwrap();
            finalize(&control, &second).await;

            // The exact request remains the retry authorization after its point records retire.
            assert!(
                control
                    .record(admitted_key(&deployment(), 0))
                    .await
                    .is_none()
            );
            assert!(control.record(anchor_key(&deployment(), 0)).await.is_none());
            drop(operator);
            assert!(chain.registration(&context).await.unwrap().is_none());

            let mut unavailable = client_with_holders(&context, &control, UNREACHABLE);
            let mut alice = Agent::open(alice_database.path(), 0).unwrap();
            assert!(
                alice
                    .claim_withdrawal(&context, &mut unavailable, UNREACHABLE)
                    .await
                    .is_err()
            );
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            assert!(alice.pending_withdrawal_claim.is_none());
            drop(alice);

            let mut alice = Agent::open(alice_database.path(), 0).unwrap();
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            let claim = alice
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await;
            if already_released {
                assert!(claim.is_err());
                assert!(alice.pending_withdrawal_claim.is_none());
            } else {
                assert_eq!(claim.unwrap().amount, 25);
            }
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            assert_eq!(
                chain
                    .native_balance(&context, native_chain_id, wallets()[0].public_key())
                    .await
                    .unwrap(),
                native_before + 25
            );
            drop(alice);
            let alice = Agent::open(alice_database.path(), 0).unwrap();
            assert!(alice.pending_withdrawal_claim.is_none());
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            assert_eq!(chain.status(&context).await.unwrap().claimable, 0);
        });
    }
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
        assert_eq!(order.len(), 4);

        let garbage = garbage_holder(
            &context,
            order[0],
            rpc::Response::Success {
                body: Bytes::from_static(b"not an evidence response"),
            },
        )
        .await;
        let mut forged = genesis_cache().opening(&account).unwrap();
        forged.balance = NonZeroU64::new(forged.balance.get() + 1).unwrap();
        let forger = garbage_holder(
            &context,
            order[1],
            rpc::Response::Success {
                body: EvidenceResponse::Served(Evidence::State(StateLookup::Present(
                    StateValueOpening {
                        balance: forged.balance,
                        proof: forged.proof,
                    },
                )))
                .encode(),
            },
        )
        .await;
        let honest = forwarding_holder(&context, order[2], Duration::ZERO).await;

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
        assert_eq!(order.len(), 4);

        let last = forwarding_holder(&context, *order.last().unwrap(), Duration::ZERO).await;
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
/// the frozen root. Recovery opens it through the validators, verified
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
        let _registered_epoch = registered_context(&control).await;
        let _registered = _registered_epoch.payment().clone();
        let height = control.advance(0).await;
        let mut faulted = status(&control).await;
        while !faulted.hard_faulted {
            let advanced = control.advance(1).await;
            assert!(advanced < height + 30, "the deployment never faulted");
            faulted = status(&control).await;
        }
        assert_eq!(faulted.state_root, frozen_root);

        let mut passive = Agent::new(0).unwrap();
        assert!(
            passive
                .store
                .recovery_opening(&frozen_root)
                .unwrap()
                .is_none()
        );
        let Some(release) = passive
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap()
        else {
            panic!("expected a positive frozen balance")
        };
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, INITIAL_BALANCE);

        let mut dead = client_with_holders(&context, &control, UNREACHABLE);
        let mut stranded = Agent::new(1).unwrap();
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
/// holder-served opening and claims the finalized withdrawal from configured native custody,
/// while the active authorization blocks an overlapping payment.
#[test]
fn operator_dark_wallet_moves_finalized_claim_to_registered_operator() {
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
        let listener = withdrawing.await.unwrap();

        // The queued request is a chain obligation the operator's registration
        // must carry verbatim.
        operator.apply_withdrawal(request, true).unwrap();
        register(&control, &mut operator).await;

        // The still-active withdrawal authorization is a signer barrier. It must be resolved or
        // expire under a healthy certified height before another balance-consuming action signs.
        let blocked = agent
            .pay(&context, &mut chain, address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{blocked:#}").contains("withdrawal authorization is still active"));
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
        assert!(agent.pending_payment.is_none());

        // The close carrying the withdrawal is only admitted, so the wallet retains the request
        // hint without caching an unfinalized payout candidate.
        let result = operator.complete_close(80).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
        let waiting = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap_err();
        assert!(
            format!("{waiting:#}").contains("no withdrawal epoch is finalized"),
            "{waiting:#}"
        );
        assert!(agent.pending_withdrawal_claim.is_none());
        drop(listener);
        drop(operator);

        // After finalization the cached claim releases against the certified
        // batch, and the refused acknowledgement holds nothing open.
        let chain_id = chain.genesis().native.chain_id();
        let native_before = chain
            .native_balance(&context, chain_id, agent.account())
            .await
            .unwrap();
        agent
            .transfer_native(&context, &mut chain, operator_key(), native_before)
            .await
            .unwrap();
        let native_before = chain
            .native_balance(&context, chain_id, agent.account())
            .await
            .unwrap();
        assert_eq!(native_before, 0);
        finalize(&control, &result).await;
        let release = agent
            .claim_withdrawal(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(release.amount, 5);
        assert_eq!(release.destination.as_ref(), agent.account().as_ref());
        assert_eq!(
            chain
                .native_balance(&context, chain.genesis().native.chain_id(), agent.account())
                .await
                .unwrap(),
            native_before + release.amount
        );
        assert!(agent.pending_withdrawal_claim.is_none());

        // A separate wallet funds registration, so the withdrawing wallet deposits only its
        // finalized release into the destination's initially empty custody.
        let destination_operator = Wallet::from_seed("destination operator", 99);
        let fee = chain.genesis().native.registration_fee;
        let mut funder = Agent::new(1).unwrap();
        funder
            .transfer_native(&context, &mut chain, destination_operator.public_key(), fee)
            .await
            .unwrap();
        let registration = crate::chain::tx::RegisterDeploymentRequest::sign(
            chain_id,
            Sha256::hash(&[b"wallet destination deployment"]),
            crate::protocol::operator_ack_key(99),
            chain.genesis().native.deployments[0].network_key.clone(),
            1024,
            fee,
            destination_operator.signer(),
        );
        let destination = registration.deployment_id();
        chain
            .deliver(&context, &SettlementTx::RegisterDeployment(registration))
            .await
            .unwrap();
        let mut destination_chain = Client::new(
            control.identity(),
            destination,
            vec![CHAIN],
            context.child("destination_chain"),
        )
        .unwrap();
        let registered = destination_chain.registered(&context).await.unwrap();
        assert_eq!(
            registered.deployment.operator,
            destination_operator.public_key()
        );
        assert!(registered.deployment.accounts.is_empty());
        let destination_database = TempDatabase::new();
        let mut destination_wallet = Agent::open_for(
            destination_database.path(),
            0,
            destination,
            registered.deployment.operator,
        )
        .unwrap();
        destination_wallet
            .deposit(&context, &mut destination_chain, release.amount)
            .await
            .unwrap();
        assert_eq!(
            destination_chain.status(&context).await.unwrap().custody,
            release.amount
        );
        assert_eq!(
            chain
                .native_balance(&context, chain_id, agent.account())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            destination_chain
                .native_balance(&context, chain_id, agent.account())
                .await
                .unwrap(),
            0
        );
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.store.debits_since(0).unwrap(), 0);
        assert!(recovered.pending_withdrawal_claim.is_none());
    });
}

#[test]
fn ui_retries_a_durable_payment_after_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let staging = context.child("lost_reply").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert!(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .is_err()
        );
        let original = agent
            .pending_payment
            .as_ref()
            .unwrap()
            .authorization
            .clone();
        drop(agent);
        let (mut listener, mut operator) = staging.await.unwrap();
        let server = context.child("operator").spawn(move |_| async move {
            loop {
                respond(&mut listener, |request| {
                    if let operator_rpc::OperatorRequest::AcceptSend(send) = &request {
                        assert_eq!(send.authorization, original);
                    }
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let started = context.current();
        let mut retry = true;
        crate::ui::run_with_io(
            &context,
            address,
            &mut chain,
            &mut agent,
            |_, _| Ok(()),
            || {
                let key = if retry {
                    retry = false;
                    Some('R')
                } else if context.current().duration_since(started).unwrap()
                    >= Duration::from_secs(3)
                {
                    Some('q')
                } else {
                    None
                };
                Ok(key.map(|key| {
                    crossterm::event::KeyEvent::new(
                        crossterm::event::KeyCode::Char(key),
                        crossterm::event::KeyModifiers::NONE,
                    )
                }))
            },
        )
        .await
        .unwrap();
        server.abort();
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.receipt_count(), 1);
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.receipt_count(), 1);
    });
}

#[test]
fn invalidated_receipt_is_protected_across_fault_order_and_restart() {
    #[derive(Clone, Copy)]
    enum FaultOrder {
        ChallengeFirst,
        TimeoutFirst,
    }

    for (epoch, settling, order) in [
        (5, true, FaultOrder::TimeoutFirst),
        (0, false, FaultOrder::ChallengeFirst),
        (0, true, FaultOrder::ChallengeFirst),
        (5, false, FaultOrder::ChallengeFirst),
        (5, true, FaultOrder::ChallengeFirst),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let control = harness::start_with_native(
                &context,
                CHAIN,
                "chain",
                harness::native(crate::protocol::deployments()),
                crate::protocol::Timing {
                    admission_offset: 100,
                    challenge_duration: 100,
                },
            )
            .await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            for predecessor in 0..epoch {
                register(&control, &mut operator).await;
                operator.pay(2, 3, 1).unwrap();
                let result = operator.complete_close(70 + predecessor).unwrap();
                applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
            }
            let payment = register(&control, &mut operator).await;
            assert_eq!(payment.epoch(), epoch);
            let receipt = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 5);
            operator.pay(2, 3, 1).unwrap();
            let result = operator.complete_close(70 + epoch).unwrap();
            applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
            let committed = operator
                .committed_entry(&wallets()[0].public_key(), &receipt.recipient, epoch)
                .unwrap();
            let batch_id = result.header.batch_id::<Sha256>();
            let evidence_address = SocketAddr::from(([127, 0, 0, 1], 9_603));
            let mut chain = client_with_holders(&context, &control, evidence_address);
            assert!(status(&control).await.last_finalized.is_none());
            for pending in 0..=epoch {
                assert!(
                    !chain
                        .admitted(&context, pending)
                        .await
                        .unwrap()
                        .unwrap()
                        .finalized
                );
            }
            let mut agent = Agent::open(database.path(), 1).unwrap();
            let mut listener = context.bind(UNREACHABLE).await.unwrap();
            let served_receipt = receipt.clone();
            let server = context.child("intake").spawn(move |_| async move {
                respond(&mut listener, |_| rpc::Response::Success {
                    body: incoming_response(&[(served_receipt, 1)]).encode(),
                })
                .await;
            });
            agent
                .intake_incoming(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(agent.incoming().total, 5);
            assert_eq!(agent.store.unreconciled_incoming_epochs().unwrap(), [epoch]);
            let fetched = match order {
                FaultOrder::ChallengeFirst => garbage_holder(
                    &context,
                    evidence_address,
                    rpc::error_response("evidence withheld".into()),
                ).await,
                FaultOrder::TimeoutFirst => {
                    forwarding_holder(&context, evidence_address, Duration::ZERO).await
                }
            };
            match order {
                FaultOrder::ChallengeFirst => {
                    let challenge = commonware_clearing::bajillion::challenge::Challenge::HigherAckEntry {
                        entry: Box::new(commonware_clearing::bajillion::challenge::EntryWitness {
                            ack: commonware_clearing::bajillion::challenge::AckWitness::from_ack(
                                &receipt.ack,
                            ),
                            recipient: agent.account(),
                            cumulative: receipt.cumulative,
                            count: receipt.count,
                            opening: receipt.opening,
                        }),
                        sender: Box::new(committed),
                    };
                    control
                        .submit(SettlementTx::Challenge(
                            crate::chain::tx::ChallengeRequest {
                                deployment: deployment(),
                                batch_id,
                                evidence: challenge.encode(),
                            },
                        ))
                        .await;
                    assert!(chain.status(&context).await.unwrap().hard_faulted);
                    assert!(matches!(
                        chain.fault(&context).await.unwrap(),
                        Some(FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge {
                            batch_id: proven,
                            ..
                        })) if proven == batch_id
                    ));
                }
                FaultOrder::TimeoutFirst => {
                    register(&control, &mut operator).await;
                    let deadline = registration_record(&control).await.admission_deadline;
                    let height = control.advance(0).await;
                    control.advance(deadline - height + 1).await;
                    assert!(matches!(
                        chain.fault(&context).await.unwrap(),
                        Some(FaultRecord::Faulted(HardFaultReasonResponse::ExpiredRegistration { .. }))
                    ));
                    let (_, before_submissions) = control.counts().await;
                    let first = agent.reconcile(&context, &mut chain, evidence_address).await.unwrap();
                    assert!(first.is_empty());
                    assert_eq!(agent.store.unreconciled_incoming_epochs().unwrap(), [epoch]);
                    let (_, after_submissions) = control.counts().await;
                    assert_eq!(after_submissions, before_submissions + 1);
                    assert!(fetched.load(Ordering::Relaxed) > 0);
                    assert!(matches!(
                        chain.fault(&context).await.unwrap(),
                        Some(FaultRecord::Faulted(HardFaultReasonResponse::ExpiredRegistration { .. }))
                    ));
                    drop(agent);
                    agent = Agent::open(database.path(), 1).unwrap();
                    assert_eq!(agent.store.unreconciled_incoming_epochs().unwrap(), [epoch]);
                }
            }
            if settling {
                // Terminal settlement waits for the valid predecessor closes to finalize.
                let deadline = result.context.epoch_context().challenge_deadline();
                let height = control.advance(0).await;
                if height <= deadline {
                    control.advance(deadline - height + 1).await;
                }
                assert_eq!(status(&control).await.last_finalized, epoch.checked_sub(1));
                control
                    .submit(SettlementTx::BeginHardFaultSettlement(
                        crate::chain::tx::BeginHardFaultSettlementRequest {
                            deployment: deployment(),
                        },
                    ))
                    .await;
                let Some(FaultRecord::Settling(snapshot)) = chain.fault(&context).await.unwrap() else {
                    panic!("terminal settlement was not published");
                };
                assert_eq!(snapshot.invalid_from, Some(batch_id));
            }
            let fetched_after_challenge = fetched.load(Ordering::Relaxed);
            let (_, submissions_before_reconcile) = control.counts().await;
            let summary = agent
                .reconcile(&context, &mut chain, evidence_address)
                .await
                .unwrap();
            assert_eq!(summary.protected, [epoch]);
            assert!(summary.convicted.is_empty());
            assert!(summary.unenforceable.is_empty());
            assert_eq!(agent.last_reconciled_epoch(), None);
            assert_eq!(fetched.load(Ordering::Relaxed), fetched_after_challenge);
            let (_, submissions_after_reconcile) = control.counts().await;
            assert_eq!(submissions_after_reconcile, submissions_before_reconcile);
            assert!(
                agent
                    .store
                    .unreconciled_incoming_epochs()
                    .unwrap()
                    .is_empty()
            );
            drop(agent);
            let mut agent = Agent::open(database.path(), 1).unwrap();
            assert!(
                agent
                    .store
                    .unreconciled_incoming_epochs()
                    .unwrap()
                    .is_empty()
            );
            let summary = agent
                .reconcile(&context, &mut chain, evidence_address)
                .await
                .unwrap();
            assert!(summary.is_empty());
            assert_eq!(fetched.load(Ordering::Relaxed), fetched_after_challenge);
            let (_, submissions_after_reconcile) = control.counts().await;
            assert_eq!(submissions_after_reconcile, submissions_before_reconcile);
        });
    }
}

#[test]
fn healthy_expiry_retires_authorization_before_other_actions() {
    for next in ["pay", "withdraw"] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
            let stale = status(&control).await;
            let stale_request = ReadRequest::new(deployment(), Lookup::Status);
            let stale_response = control.read(stale_request.clone()).await;
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let WithdrawalOutcome::Signed { request, .. } = agent
                .withdraw(&context, &mut chain, UNREACHABLE, action)
                .await
                .unwrap()
            else {
                panic!("operator is unavailable");
            };
            drop(agent);
            let height = control.advance(0).await;
            control
                .advance(request.body().deadline().saturating_sub(height))
                .await;
            assert!(!status(&control).await.hard_faulted);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            agent
                .observe_withdrawal_expiry(&context, &mut chain)
                .await
                .unwrap();
            assert!(agent.pending_withdrawal.is_none());
            drop(agent);
            register(&control, &mut operator).await;
            let raw = operator.payment_head(&wallets()[0].public_key()).unwrap();
            let old_head = operator_rpc::PaymentHeadResponse {
                context: raw.context,
                balance: raw.balance,
                root: raw.root,
                opening: raw.opening,
            };

            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 9_853)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let source = control.clone();
            let encoded_stale_request = stale_request.encode();
            context
                .child("retired_withdrawal_stale_status")
                .spawn(move |_| async move {
                    loop {
                        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                        let request = rpc::recv_request(&mut stream).await.unwrap();
                        let body = if request.body == encoded_stale_request {
                            stale_response.encode()
                        } else {
                            source
                                .read(ReadRequest::decode(request.body).unwrap())
                                .await
                                .encode()
                        };
                        rpc::send_response(&mut sink, &rpc::Response::Success { body })
                            .await
                            .unwrap();
                    }
                });
            let mut stale_chain = Client::new(
                control.identity(),
                deployment(),
                vec![address],
                context.child("stale_withdrawal_rng"),
            )
            .unwrap();
            assert_eq!(
                stale_chain.status(&context).await.unwrap().height,
                stale.height
            );
            let mut old_operator = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 9_855)))
                .await
                .unwrap();
            let old_operator_address = old_operator.local_addr().unwrap();
            let old_operator_server =
                context
                    .child("retired_withdrawal_old_head")
                    .spawn(move |_| async move {
                        respond(&mut old_operator, |request| {
                            assert!(matches!(
                                request,
                                operator_rpc::OperatorRequest::PaymentHead(_)
                            ));
                            rpc::Response::Success {
                                body: old_head.encode(),
                            }
                        })
                        .await;
                    });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert_eq!(
                agent
                    .balance(&context, &mut stale_chain, old_operator_address)
                    .await
                    .unwrap(),
                INITIAL_BALANCE
            );
            assert!(agent.cache.is_none());
            let mut stage_chain = Client::new(
                control.identity(),
                deployment(),
                vec![address],
                context.child("stale_withdrawal_stage_rng"),
            )
            .unwrap();
            assert_eq!(
                stage_chain.status(&context).await.unwrap().height,
                stale.height
            );
            let error = agent
                .pay(&context, &mut stage_chain, UNREACHABLE, &[(1, 1)])
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("predates a retired withdrawal"),
                "{error:#}"
            );
            assert!(agent.pending_payment.is_none());
            assert!(agent.cache.is_none());
            old_operator_server.await.unwrap();
            drop(agent);

            let mut agent = Agent::open(database.path(), 0).unwrap();
            if next == "pay" {
                assert!(
                    agent
                        .pay(&context, &mut chain, UNREACHABLE, &[(1, 1)])
                        .await
                        .is_err()
                );
                assert!(agent.pending_withdrawal.is_none());
                assert!(agent.pending_payment.is_some());
            } else {
                let WithdrawalOutcome::Signed {
                    request: replacement,
                    ..
                } = agent
                    .withdraw(&context, &mut chain, UNREACHABLE, WithdrawalAction::Close)
                    .await
                    .unwrap()
                else {
                    panic!("unavailable operator acknowledged replacement");
                };
                assert_eq!(replacement.body().action(), &WithdrawalAction::Close);
                assert!(replacement.body().deadline() > request.body().deadline());
                assert_eq!(agent.pending_withdrawal.as_ref(), Some(&replacement));
            }
            assert_eq!(
                agent.store.retired_withdrawal_deadline().unwrap(),
                Some(request.body().deadline())
            );
        });
    }
}

#[test]
fn expired_unacknowledged_withdrawal_retires_into_the_signing_floor() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        const HISTORY_BEFORE: u64 = 20;
        const HISTORY_AFTER: u64 = 20;

        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        for nonce in 0..HISTORY_BEFORE {
            register(&control, &mut operator).await;
            operator.pay(2, 3, 1).unwrap();
            let result = operator.complete_close(9_000 + nonce).unwrap();
            finalize(&control, &result).await;
        }

        let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let WithdrawalOutcome::Signed { request, .. } = agent
            .withdraw(&context, &mut chain, UNREACHABLE, action)
            .await
            .unwrap()
        else {
            panic!("unavailable operator unexpectedly acknowledged the withdrawal");
        };

        // A different same-account authorization deliberately produces identical output bytes.
        // It is only an advisory discovery candidate for the wallet-owned payout.
        let other = SignedWithdrawal::sign(
            deployment(),
            *request.body().state_root(),
            agent.account().encode(),
            action,
            request.body().deadline().checked_sub(1).unwrap(),
            agent.wallet.signer(),
        );
        assert_ne!(other, request);
        operator.apply_withdrawal(other.clone(), false).unwrap();
        for nonce in 0..HISTORY_AFTER {
            register(&control, &mut operator).await;
            operator.pay(2, 3, 1).unwrap();
            let result = operator
                .complete_close(9_000 + HISTORY_BEFORE + nonce)
                .unwrap();
            finalize(&control, &result).await;
        }
        let status = status(&control).await;
        assert!(status.height >= request.body().deadline());
        assert!(!status.hard_faulted);
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        assert!(control.record(anchor_key(&deployment(), 0)).await.is_none());

        let WithdrawalOutcome::Signed {
            request: replacement,
            ..
        } = agent
            .withdraw(&context, &mut chain, UNREACHABLE, action)
            .await
            .unwrap()
        else {
            panic!("unavailable operator acknowledged the replacement");
        };
        assert_ne!(replacement, request);
        assert!(replacement.body().deadline() > request.body().deadline());
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&replacement));
        assert_eq!(
            agent.store.retired_withdrawal_deadline().unwrap(),
            Some(request.body().deadline())
        );
    });
}

#[test]
fn virtual_receiver_retains_credit_then_exits_and_receives_again() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut receiver = Agent::open(database.path(), wallets().len()).unwrap();
        let account = receiver.account();
        let chain_id = chain.genesis().native.chain_id();
        assert_eq!(
            chain
                .native_balance(&context, chain_id, account.clone())
                .await
                .unwrap(),
            0
        );
        register(&control, &mut operator).await;
        operator.pay(0, operator.wallet_count(), 7).unwrap();
        let rows = operator.incoming_payments(&account, 0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let held = incoming_response(&[(rows[0].receipt.clone(), rows[0].sequence)]);
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context
            .child("first_virtual_receipt")
            .spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::IncomingPayments(_)
                    ));
                    rpc::Response::Success {
                        body: held.encode(),
                    }
                })
                .await;
            });
        receiver
            .intake_incoming(&context, &mut chain, address)
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(receiver.incoming().total, 7);
        assert!(receiver.pending_withdrawal_claim.is_none());
        drop(receiver);
        let mut receiver = Agent::open(database.path(), wallets().len()).unwrap();
        assert_eq!(receiver.incoming().total, 7);
        let first = operator.complete_close(1).unwrap();
        finalize(&control, &first).await;
        assert_eq!(
            receiver
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            7
        );
        assert_eq!(
            chain
                .native_balance(&context, chain_id, account.clone())
                .await
                .unwrap(),
            0
        );
        assert_eq!(chain.status(&context).await.unwrap().claimable, 0);
        assert_eq!(
            receiver
                .reconcile(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .reconciled,
            [0]
        );

        let WithdrawalOutcome::Signed { request, .. } = receiver
            .withdraw(&context, &mut chain, UNREACHABLE, WithdrawalAction::Close)
            .await
            .unwrap()
        else {
            panic!("unavailable operator acknowledged the withdrawal");
        };
        operator.apply_withdrawal(request, false).unwrap();
        register(&control, &mut operator).await;
        let exit = operator.complete_close(2).unwrap();
        finalize(&control, &exit).await;
        assert_eq!(
            receiver
                .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap()
                .amount,
            7
        );
        assert_eq!(
            receiver
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            chain
                .native_balance(&context, chain_id, account.clone())
                .await
                .unwrap(),
            7
        );

        register(&control, &mut operator).await;
        operator.pay(1, operator.wallet_count(), 5).unwrap();
        let recreated = operator.complete_close(3).unwrap();
        finalize(&control, &recreated).await;
        drop(receiver);
        let mut receiver = Agent::open(database.path(), wallets().len()).unwrap();
        assert_eq!(
            receiver
                .balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            5
        );
        assert_eq!(receiver.incoming().total, 7);
        assert_eq!(
            chain
                .native_balance(&context, chain_id, account)
                .await
                .unwrap(),
            7
        );
        assert_eq!(chain.status(&context).await.unwrap().claimable, 0);
    });
}

#[test]
fn virtual_receiver_spends_from_admitted_predecessor_before_finalization() {
    for operator_head in [true, false] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            register(&control, &mut operator).await;
            operator.pay(0, operator.wallet_count(), 7).unwrap();
            let first = operator.complete_close(1).unwrap();
            applied(&control, &SettlementTx::Admit(AdmitRequest::from(&first))).await;
            assert!(
                !chain
                    .admitted(&context, 0)
                    .await
                    .unwrap()
                    .unwrap()
                    .finalized
            );
            register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = context
                .child("admitted_virtual_payer")
                .spawn(move |_| async move {
                    for _ in 0..2 {
                        respond(&mut listener, |request| {
                            if !operator_head
                                && matches!(request, operator_rpc::OperatorRequest::PaymentHead(_))
                            {
                                return rpc::Response::Error {
                                    error: Bytes::from_static(b"head unavailable"),
                                };
                            }
                            operator_rpc::handle_decoded(&mut operator, request)
                        })
                        .await;
                    }
                });
            let mut receiver = Agent::open(database.path(), wallets().len()).unwrap();
            assert!(
                receiver
                    .withdraw(&context, &mut chain, UNREACHABLE, WithdrawalAction::Close)
                    .await
                    .is_err()
            );
            assert!(receiver.pending_withdrawal.is_none());
            assert!(receiver.pending_withdrawal_claim.is_none());
            let sent = accepted(
                receiver
                    .pay(&context, &mut chain, address, &[(1, 3)])
                    .await
                    .unwrap(),
            );
            assert_eq!(sent.total, 3);
            assert_eq!(sent.epoch, 1);
            assert_eq!(sent.sequence, 1);
            assert!(receiver.pending_payment.is_none());
            assert_eq!(receiver.cache.as_ref().unwrap().root, first.roots.successor);
            assert_eq!(receiver.cache.as_ref().unwrap().epoch, 1);
            assert!(
                chain
                    .status(&context)
                    .await
                    .unwrap()
                    .last_finalized
                    .is_none()
            );
            server.await.unwrap();
            drop(receiver);
            let receiver = Agent::open(database.path(), wallets().len()).unwrap();
            assert_eq!(receiver.cache.as_ref().unwrap().root, first.roots.successor);
            assert_eq!(receiver.receipt_count(), 1);
        });
    }
}

#[test]
fn invalidated_first_virtual_credit_recovers_no_frozen_balance() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let frozen = chain.status(&context).await.unwrap().state_root;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let payment = register(&control, &mut operator).await;
        operator.pay(0, operator.wallet_count(), 7).unwrap();
        let first = operator.complete_close(1).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&first))).await;
        register(&control, &mut operator).await;
        let account = crate::protocol::eve_wallet().public_key();
        let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
        let mut receiver = Agent::open(database.path(), wallets().len()).unwrap();
        let pending = receiver
            .holders
            .successor_opening(&context, &chain, &account, &admitted)
            .await
            .unwrap();
        receiver
            .retain_head(&first.roots.successor, &pending)
            .unwrap();
        assert!(receiver.store.recovery_opening(&frozen).unwrap().is_none());
        let held = issued_receipt(&payment, &wallets()[0], &account, 8);
        let committed = operator
            .committed_entry(&wallets()[0].public_key(), &account, 0)
            .unwrap();
        let challenge = commonware_clearing::bajillion::challenge::Challenge::HigherAckEntry {
            entry: Box::new(commonware_clearing::bajillion::challenge::EntryWitness {
                ack: commonware_clearing::bajillion::challenge::AckWitness::from_ack(&held.ack),
                recipient: account.clone(),
                cumulative: 8,
                count: 1,
                opening: held.opening,
            }),
            sender: Box::new(committed),
        };
        control
            .submit(SettlementTx::Challenge(
                crate::chain::tx::ChallengeRequest {
                    deployment: deployment(),
                    batch_id: first.header.batch_id::<Sha256>(),
                    evidence: challenge.encode(),
                },
            ))
            .await;
        assert!(chain.status(&context).await.unwrap().hard_faulted);
        drop(receiver);
        let mut receiver = Agent::open(database.path(), wallets().len()).unwrap();
        assert!(
            receiver
                .store
                .recovery_opening(&first.roots.successor)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            receiver
                .recover_hard_fault(&context, &mut chain)
                .await
                .unwrap(),
            None
        );
        assert_eq!(chain.status(&context).await.unwrap().state_root, frozen);
        assert_eq!(
            chain
                .native_balance(&context, chain.genesis().native.chain_id(), account.clone())
                .await
                .unwrap(),
            0
        );
        assert!(chain.hard_fault(&context, account).await.unwrap().is_none());
    });
}

#[test]
fn admitted_withdrawal_boundary_replaces_the_older_balance_floor() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(10).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 85).unwrap();
        operator.pay(2, 0, 10).unwrap();
        let first = operator.complete_close(1).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&first))).await;
        register(&control, &mut operator).await;
        let mut alice = Agent::new(0).unwrap();
        let error = alice
            .pay(&context, &mut chain, UNREACHABLE, &[(1, 16)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("insufficient available balance"));
        assert!(alice.pending_payment.is_none());
        assert!(
            chain
                .status(&context)
                .await
                .unwrap()
                .last_finalized
                .is_none()
        );
    });
}

#[test]
fn stale_finalized_head_cannot_override_admitted_withdrawal() {
    deterministic::Runner::default().start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let first_head = operator.payment_head(&wallets()[0].public_key()).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(10).unwrap()))
            .unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 85).unwrap();
        operator.pay(2, 0, 10).unwrap();
        let first = operator.complete_close(1).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&first))).await;
        register(&control, &mut operator).await;
        let current = operator.payment_head(&wallets()[0].public_key()).unwrap();
        let stale = operator_rpc::PaymentHeadResponse {
            context: current.context,
            balance: first_head.balance,
            root: first_head.root,
            opening: first_head.opening,
        };
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let submitted = Arc::new(AtomicUsize::new(0));
        let counted = submitted.clone();
        let server = context
            .child("stale_finalized_head")
            .spawn(move |_| async move {
                loop {
                    respond(&mut listener, |request| match request {
                        operator_rpc::OperatorRequest::PaymentHead(_) => rpc::Response::Success {
                            body: stale.encode(),
                        },
                        operator_rpc::OperatorRequest::AcceptSend(_) => {
                            counted.fetch_add(1, Ordering::SeqCst);
                            rpc::Response::Error {
                                error: Bytes::from_static(b"unaffordable successor payment"),
                            }
                        }
                        _ => panic!("unexpected stale-head request"),
                    })
                    .await;
                }
            });
        let mut alice = Agent::new(0).unwrap();
        assert!(
            alice
                .pay(&context, &mut chain, address, &[(1, 16)])
                .await
                .is_err()
        );
        assert_eq!(submitted.load(Ordering::SeqCst), 0);
        assert!(alice.pending_payment.is_none());
        assert!(alice.cache.is_none());
        server.abort();
    });
}

#[test]
fn frozen_recovery_preserves_finalized_withdrawals_without_history() {
    for (carried, cached, history_available) in [
        (false, false, true),
        (false, false, false),
        (true, false, true),
        (true, true, true),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut alice = Agent::open(database.path(), 0).unwrap();
            let WithdrawalOutcome::Signed { request, .. } = alice
                .withdraw(&context, &mut chain, UNREACHABLE, WithdrawalAction::Close)
                .await
                .unwrap()
            else {
                panic!("the unavailable operator acknowledged the request")
            };
            if carried {
                operator.apply_withdrawal(request.clone(), false).unwrap();
            }
            register(&control, &mut operator).await;
            if !carried {
                assert_eq!(
                    alice
                        .escalate_withdrawal(&context, &mut chain)
                        .await
                        .unwrap(),
                    request
                );
                operator.pay(0, 1, INITIAL_BALANCE).unwrap();
            }
            let withdrawals = operator.registration_boundary().unwrap().1;
            let close = operator.complete_close(1).unwrap();
            finalize(&control, &close).await;
            let cached_source = if cached {
                let (source_request, position, claim) =
                    settlement_withdrawal(&operator, &close, &withdrawals, &alice.account());
                assert_eq!(source_request, request);
                let candidate = PendingWithdrawalClaim {
                    head: close.roots.withdrawal_outputs,
                    claim,
                };
                alice.store.cache_withdrawal_claim(&candidate).unwrap();
                alice.pending_withdrawal_claim = Some(candidate);
                Some(position)
            } else {
                None
            };
            let fault_at = if carried {
                register(&control, &mut operator).await;
                registration_record(&control).await.admission_deadline + 1
            } else {
                request.body().deadline()
            };
            let height = control.advance(0).await;
            control
                .advance((fault_at - 1).checked_sub(height).unwrap())
                .await;
            assert!(!status(&control).await.hard_faulted);
            control.advance(1).await;
            assert!(status(&control).await.hard_faulted);
            assert_eq!(status(&control).await.state_root, close.roots.successor);
            drop(alice);
            let mut alice = Agent::open(database.path(), 0).unwrap();
            if !history_available {
                let wrong_root = SocketAddr::from(([127, 0, 0, 1], 9_801));
                garbage_holder(
                    &context,
                    wrong_root,
                    rpc::Response::Success {
                        body: {
                            let opening = genesis_cache().opening(&alice.account()).unwrap();
                            EvidenceResponse::Served(Evidence::State(StateLookup::Present(
                                StateValueOpening {
                                    balance: opening.balance,
                                    proof: opening.proof,
                                },
                            )))
                            .encode()
                        },
                    },
                )
                .await;
                let mut forged = client_with_holders(&context, &control, wrong_root);
                assert!(
                    alice
                        .recover_hard_fault(&context, &mut forged)
                        .await
                        .is_err()
                );
                assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
                let body = rpc::invoke(
                    &context,
                    CHAIN,
                    "validator",
                    METHOD_EVIDENCE,
                    EvidenceRequest::new(
                        deployment(),
                        EvidenceLookup::State {
                            root: close.roots.successor,
                            operations: close.roots.successor_operations,
                            account: alice.account(),
                        },
                    )
                    .encode(),
                )
                .await
                .unwrap();
                let address = SocketAddr::from(([127, 0, 0, 1], 9_800));
                garbage_holder(&context, address, rpc::Response::Success { body }).await;
                let mut unavailable = client_with_holders(&context, &control, address);
                assert_eq!(
                    alice
                        .recover_hard_fault(&context, &mut unavailable)
                        .await
                        .unwrap(),
                    None
                );
                assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
                drop(alice);
                alice = Agent::open(database.path(), 0).unwrap();
                assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            }
            assert_eq!(
                alice
                    .recover_hard_fault(&context, &mut chain)
                    .await
                    .unwrap(),
                None
            );
            assert!(
                chain
                    .hard_fault(&context, alice.account())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            if let Some(position) = cached_source {
                let candidate = alice.pending_withdrawal_claim.as_ref().unwrap();
                assert_eq!(candidate.claim.position(), position);
            }
            drop(alice);
            let mut alice = Agent::open(database.path(), 0).unwrap();
            assert_eq!(alice.pending_withdrawal.as_ref(), Some(&request));
            for index in 1..wallets().len() {
                let mut other = Agent::new(index).unwrap();
                assert!(
                    other
                        .recover_hard_fault(&context, &mut chain)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
            assert_eq!(chain.status(&context).await.unwrap().custody, 0);
            if carried {
                assert_eq!(
                    alice
                        .claim_withdrawal(&context, &mut chain, UNREACHABLE)
                        .await
                        .unwrap()
                        .amount,
                    INITIAL_BALANCE
                );
            }
            assert!(alice.pending_withdrawal_claim.is_none());
        });
    }
}

#[test]
fn finalized_omission_never_promotes_a_first_time_receipt() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let fixture = Box::pin(admit_omitting(&context, &control)).await;
        finalize_omitting(&control, &fixture).await;
        let receipt = fixture.held_receipt;
        receipt
            .verify::<Sha256>(fixture.result.context.payment())
            .unwrap();
        let payer = receipt.ack.body().payer().clone();
        let id = Sha256::hash(&[receipt.ack.body().encode().as_ref()]);
        let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
        assert!(admitted.finalized);
        assert_eq!(
            chain.anchor(&context, 0).await.unwrap(),
            Some(*receipt.ack.body().anchor())
        );
        let lookup = Holders::default()
            .committed_entry_at(
                &context,
                &chain,
                0,
                &admitted.activity_range(),
                &payer,
                &receipt.recipient,
            )
            .await
            .unwrap();
        assert_eq!(
            lookup
                .resolve::<Sha256>(&admitted.activity_range(), &payer, &receipt.recipient)
                .unwrap(),
            (0, 0)
        );
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let server = context
            .child("excluded_late_receipt")
            .spawn(move |_| async move {
                respond(&mut listener, |_| rpc::Response::Success {
                    body: incoming_response(&[(receipt, 1)]).encode(),
                })
                .await;
            });
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        receiver
            .intake_incoming(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 0,
                count: 0,
                cursor: 1
            }
        );
        assert_eq!(receiver.store.credits_since(0).unwrap(), 0);
        assert!(!receiver.has_receipt(&payer, &id).unwrap());
        assert!(receiver.store.held_edge(&payer, 0).unwrap().is_none());
        drop(receiver);
        let receiver = Agent::open(database.path(), 1).unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 0,
                count: 0,
                cursor: 1
            }
        );
        assert_eq!(receiver.store.credits_since(0).unwrap(), 0);
        server.await.unwrap();
    });
}

#[test]
fn payment_conclusion_retires_its_context_in_the_same_commit() {
    for conclusion in ["accepted", "abandoned", "held", "unheld"] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let payment = register(&control, &mut operator).await;
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let raw = operator.payment_head(&agent.account()).unwrap();
            let head = operator_rpc::PaymentHeadResponse {
                context: raw.context,
                balance: raw.balance,
                root: raw.root,
                opening: raw.opening,
            };
            agent
                .verify_head(&context, &mut chain, &head, &status(&control).await)
                .await
                .unwrap();
            let entries = vec![Entry {
                recipient: wallets()[1].public_key(),
                amount: 7,
            }];
            let vector = OutVector::new(0, agent.account(), bob_edge(7, 1)).unwrap();
            let body = VectorSendBody::new(
                &payment,
                agent.account(),
                1,
                7,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            let authorization = SendAuthorization::sign(body, agent.wallet.signer());
            agent
                .store
                .stage_payment(&authorization, &entries, &head.root, 0)
                .unwrap();
            let accepted = if conclusion == "abandoned" {
                operator.pay(2, 3, 1).unwrap();
                None
            } else {
                Some(
                    operator
                        .accept_send(authorization.clone(), entries.clone())
                        .unwrap()
                        .into_accepted(),
                )
            };
            if conclusion != "accepted" {
                let close = operator.complete_close(819).unwrap();
                if conclusion == "abandoned" {
                    applied(&control, &SettlementTx::Admit(AdmitRequest::from(&close))).await;
                } else {
                    finalize(&control, &close).await;
                }
                let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
                assert_eq!(admitted.finalized, conclusion != "abandoned");
                let lookup = Holders::default()
                    .committed_account_at(
                        &context,
                        &chain,
                        0,
                        &admitted.activity_range(),
                        &agent.account(),
                    )
                    .await
                    .unwrap();
                let activity = lookup
                    .resolve::<Sha256>(&admitted.activity_range(), &agent.account())
                    .unwrap()
                    .1;
                if conclusion == "abandoned" {
                    assert!(activity.is_none_or(|entry| !entry.has_outgoing()));
                } else {
                    assert!(
                        activity
                            .unwrap()
                            .matches_outgoing(&payment, authorization.body())
                    );
                }
            }
            // Dropping immediately after the conclusion models a crash before volatile cleanup.
            match conclusion {
                "abandoned" => agent.store.abandon_payment(&authorization).unwrap(),
                "unheld" => agent
                    .store
                    .finalize_payment_unheld(&authorization, &entries, 0)
                    .unwrap(),
                _ => {
                    let accepted: operator_rpc::AcceptedBatchResponse = accepted.unwrap().into();
                    agent
                        .store
                        .commit_payment(
                            &accepted.acceptance,
                            &authorization,
                            &entries,
                            0,
                            0,
                            conclusion == "held",
                        )
                        .unwrap();
                }
            }
            drop(agent);
            let mut reopened = Agent::open(database.path(), 0).unwrap();
            assert!(reopened.pending_payment.is_none());
            assert_eq!(
                reopened.cache.is_some(),
                conclusion == "accepted",
                "{conclusion}"
            );
            assert_eq!(
                reopened.store.debits_since(0).unwrap(),
                if conclusion == "abandoned" { 0 } else { 7 }
            );
            assert_eq!(
                reopened.receipt_count(),
                u64::from(matches!(conclusion, "accepted" | "held"))
            );
            if conclusion != "accepted" {
                let error = reopened
                    .store
                    .cache_context(&payment, &head.root, 0)
                    .unwrap_err();
                assert!(format!("{error:#}").contains("permanent settlement outcome"));
                reopened.ensure_store_usable().unwrap();
                assert!(reopened.cache.is_none());
                let other = PaymentContext::new(
                    Sha256::hash(&[b"other-anchor-in-the-same-epoch"]),
                    payment.epoch(),
                    operator_key(),
                );
                reopened.store.cache_context(&other, &head.root, 0).unwrap();
            }
        });
    }
}

#[test]
fn receipt_acquisition_after_successor_registration_keeps_the_challenge() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let old = register(&control, &mut operator).await;
        let receipt = issued_receipt(&old, &wallets()[0], &wallets()[1].public_key(), 5);
        operator.pay(2, 3, 1).unwrap();
        let first = operator.complete_close(798).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&first))).await;
        let next = register(&control, &mut operator).await;
        let descendant = issued_receipt(&next, &wallets()[0], &wallets()[1].public_key(), 7);
        operator.pay(2, 3, 1).unwrap();
        let second = operator.complete_close(799).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&second))).await;
        assert_eq!(registration_record(&control).await.epoch, 1);
        assert!(!chain.admitted(&context, 0).await.unwrap().unwrap().finalized);
        assert!(status(&control).await.height <= first.context.epoch_context().challenge_deadline());
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let served = receipt.clone();
        let server = context.child("live_old_receipt").spawn(move |_| async move {
            respond(&mut listener, |_| rpc::Response::Success { body: incoming_response(&[(served, 1)]).encode() }).await;
            listener
        });
        let mut receiver = Agent::new(1).unwrap();
        receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await.unwrap();
        assert_eq!(receiver.incoming(), IncomingSummary { total: 5, count: 1, cursor: 1 });
        assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
        assert!(!status(&control).await.hard_faulted);
        assert_eq!(receiver.reconcile(&context, &mut chain, UNREACHABLE).await.unwrap().convicted, [0]);
        assert!(matches!(chain.fault(&context).await.unwrap(), Some(FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge { batch_id, .. })) if batch_id == first.header.batch_id::<Sha256>()));
        let mut listener = server.await.unwrap();
        let late = context.child("invalidated_receipts").spawn(move |_| async move {
            respond(&mut listener, |_| rpc::Response::Success { body: incoming_response(&[(receipt, 1), (descendant, 2)]).encode() }).await;
        });
        let mut late_receiver = Agent::new(1).unwrap();
        late_receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await.unwrap();
        assert_eq!(late_receiver.incoming(), IncomingSummary { total: 0, count: 0, cursor: 2 });
        assert_eq!(late_receiver.store.credits_since(0).unwrap(), 0);
        assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
        late.await.unwrap();
    });
}

#[test]
fn accepted_reply_crossing_finalization_uses_the_finalized_outcome() {
    for included in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let payment = register(&control, &mut operator).await;
            let mut listener = context.bind(UNREACHABLE).await.unwrap();
            let server_control = control.clone();
            let response_context = payment.clone();
            let server = context
                .child("reply_crosses_finalization")
                .spawn(move |_| async move {
                    relay(&mut listener, &mut operator).await;
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(request) =
                        operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                            .unwrap()
                    else {
                        panic!("expected send");
                    };
                    let acceptance = issue_acceptance(
                        &Wallet::from_seed("operator", 1),
                        &[],
                        &request.authorization,
                        &request.entries,
                    );
                    acceptance.verify(&response_context).unwrap();
                    if included {
                        operator
                            .accept_send(request.authorization, request.entries)
                            .unwrap();
                    } else {
                        operator.pay(2, 3, 1).unwrap();
                    }
                    let result = operator.complete_close(800).unwrap();
                    finalize(&server_control, &result).await;
                    assert_eq!(status(&server_control).await.last_finalized, Some(0));
                    rpc::send_response(
                        &mut sink,
                        &rpc::Response::Success {
                            body: accept_response(operator_rpc::AcceptedBatchResponse {
                                epoch: 0,
                                sequence: 1,
                                total: 7,
                                acceptance,
                            }),
                        },
                    )
                    .await
                    .unwrap();
                });
            let mut payer = Agent::new(0).unwrap();
            let outcome = payer
                .pay(&context, &mut chain, UNREACHABLE, &[(1, 7)])
                .await;
            if included {
                assert_eq!(accepted(outcome.unwrap()).total, 7);
            } else {
                assert!(outcome.is_err());
            }
            assert_eq!(status(&control).await.last_finalized, Some(0));
            assert_eq!(
                payer.store.debits_since(0).unwrap(),
                if included { 7 } else { 0 }
            );
            assert_eq!(payer.receipt_count(), u64::from(included));
            assert_eq!(
                payer.store.vector_state(&payment).unwrap().is_some(),
                included
            );
            assert!(payer.pending_payment.is_none());
            assert!(payer.cache.is_none());
            server.await.unwrap();
        });
    }
}

#[test]
fn late_incoming_requires_both_finalized_endpoints() {
    for (cumulative, count, covered) in [(8, 2, true), (9, 2, false), (8, 3, false)] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let payment = register(&control, &mut operator).await;
            operator.pay(0, 1, 5).unwrap();
            operator.pay(0, 1, 3).unwrap();
            let result = operator.complete_close(801).unwrap();
            finalize(&control, &result).await;
            let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
            assert!(admitted.finalized);
            let payer = &wallets()[0];
            let recipient = wallets()[1].public_key();
            let lookup = Holders::default()
                .committed_entry_at(
                    &context,
                    &chain,
                    0,
                    &admitted.activity_range(),
                    &payer.public_key(),
                    &recipient,
                )
                .await
                .unwrap();
            assert_eq!(lookup.resolve::<Sha256>(&admitted.activity_range(), &payer.public_key(), &recipient).unwrap(), (8, 2));
            let vector = OutVector::new(0, payer.public_key(), vec![OutEntry {
                recipient: recipient.clone(), cumulative, count,
            }]).unwrap();
            let body = VectorSendBody::new(&payment, payer.public_key(), count, cumulative, vector.root::<Sha256, Digest>().unwrap());
            let authorization = SendAuthorization::sign(body, payer.signer());
            let OutTipLookup::Present { opening, .. } = vector.lookup::<Sha256, Digest>(&recipient).unwrap() else {
                panic!("the receipt entry is present");
            };
            let receipt = Receipt {
                ack: countersign(&authorization, &Wallet::from_seed("operator", 1)),
                recipient, cumulative, count, opening,
            };
            receipt.verify::<Sha256>(&payment).unwrap();
            assert_eq!(chain.anchor(&context, 0).await.unwrap(), Some(*payment.anchor()));
            let id = Sha256::hash(&[receipt.ack.body().encode().as_ref()]);
            let mut listener = context.bind(UNREACHABLE).await.unwrap();
            let server = context.child("late_receipt").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::IncomingPayments(request) if request.cursor == 0));
                    rpc::Response::Success { body: incoming_response(&[(receipt, 1)]).encode() }
                }).await;
            });
            let mut receiver = Agent::open(database.path(), 1).unwrap();
            receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await.unwrap();
            assert_eq!(receiver.incoming(), IncomingSummary { total: if covered { 8 } else { 0 }, count: u64::from(covered), cursor: 1 });
            assert_eq!(receiver.store.credits_since(0).unwrap(), if covered { 8 } else { 0 });
            assert_eq!(receiver.has_receipt(&payer.public_key(), &id).unwrap(), covered);
            receiver.ensure_store_usable().unwrap();
            drop(receiver);
            let reopened = Agent::open(database.path(), 1).unwrap();
            assert_eq!(reopened.incoming().total, if covered { 8 } else { 0 });
            assert_eq!(reopened.incoming().cursor, 1);
            assert_eq!(reopened.store.credits_since(0).unwrap(), if covered { 8 } else { 0 });
            server.await.unwrap();
        });
    }
}

#[test]
fn finalized_receipt_uses_authenticated_operator_fallback() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut healthy) = chain(&context).await;
        let mut unavailable = client_with_holders(&context, &control, UNREACHABLE);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let result = operator.complete_close(802).unwrap();
        finalize(&control, &result).await;
        assert!(
            healthy
                .admitted(&context, 0)
                .await
                .unwrap()
                .unwrap()
                .finalized
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = context
            .child("withheld_finalized_entry")
            .spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                relay(&mut listener, &mut operator).await;
                relay(&mut listener, &mut operator).await;
            });
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        receiver
            .intake_incoming(&context, &mut unavailable, address)
            .await
            .unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 5,
                count: 1,
                cursor: 1
            }
        );
        assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
        receiver.ensure_store_usable().unwrap();
        drop(receiver);
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        assert_eq!(receiver.incoming().total, 5);
        assert_eq!(receiver.incoming().cursor, 1);
        assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
        receiver
            .intake_incoming(&context, &mut healthy, address)
            .await
            .unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 5,
                count: 1,
                cursor: 1
            }
        );
        assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
        server.await.unwrap();
    });
}

#[test]
fn incoming_fault_page_commits_covered_prefix_and_retries_survivor() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let database = TempDatabase::new();
        let control = harness::start_with_native(
            &context,
            CHAIN,
            "chain",
            harness::native(crate::protocol::deployments()),
            crate::protocol::Timing {
                admission_offset: 100,
                challenge_duration: 100,
            },
        )
        .await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(0, 1, 5).unwrap();
        let first = operator.complete_close(803).unwrap();
        finalize(&control, &first).await;
        register(&control, &mut operator).await;
        operator.pay(0, 1, 7).unwrap();
        let survivor = operator.complete_close(804).unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&survivor)),
        )
        .await;
        register(&control, &mut operator).await;
        operator.pay(0, 1, 9).unwrap();
        let rows = operator
            .incoming_payments(&wallets()[1].public_key(), 0, 10)
            .unwrap();
        assert_eq!(rows.len(), 3);
        let deadline = registration_record(&control).await.admission_deadline;
        let height = control.advance(0).await;
        control.advance(deadline - height + 1).await;
        assert!(status(&control).await.hard_faulted);
        assert_eq!(status(&control).await.last_finalized, Some(0));
        assert!(
            chain
                .admitted(&context, 0)
                .await
                .unwrap()
                .unwrap()
                .finalized
        );
        assert!(
            !chain
                .admitted(&context, 1)
                .await
                .unwrap()
                .unwrap()
                .finalized
        );
        assert!(chain.admitted(&context, 2).await.unwrap().is_none());
        assert!(chain.anchor(&context, 2).await.unwrap().is_some());
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let server = context.child("faulted_page").spawn(move |_| async move {
            for expected in [0, 1] {
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::IncomingPayments(request) = request else {
                        panic!("expected intake");
                    };
                    assert_eq!(request.cursor, expected);
                    let pairs = rows
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| *index as u64 >= expected)
                        .map(|(index, row)| (row.receipt.clone(), index as u64 + 1))
                        .collect::<Vec<_>>();
                    rpc::Response::Success {
                        body: incoming_response(&pairs).encode(),
                    }
                })
                .await;
            }
        });
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        assert!(
            receiver
                .intake_incoming(&context, &mut chain, UNREACHABLE)
                .await
                .is_err()
        );
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 5,
                count: 1,
                cursor: 1
            }
        );
        assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
        receiver.ensure_store_usable().unwrap();
        drop(receiver);
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 5,
                count: 1,
                cursor: 1
            }
        );
        let height = control.advance(0).await;
        control
            .advance(survivor.context.epoch_context().challenge_deadline() - height + 1)
            .await;
        assert_eq!(status(&control).await.last_finalized, Some(1));
        assert!(status(&control).await.hard_faulted);
        receiver
            .intake_incoming(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 12,
                count: 2,
                cursor: 3
            }
        );
        assert_eq!(receiver.store.credits_since(0).unwrap(), 12);
        assert!(
            receiver
                .store
                .held_edge(&wallets()[0].public_key(), 2)
                .unwrap()
                .is_none()
        );
        drop(receiver);
        let receiver = Agent::open(database.path(), 1).unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 12,
                count: 2,
                cursor: 3
            }
        );
        server.await.unwrap();
    });
}

#[test]
fn accepted_reply_resolves_admission_exclusion_and_finalized_inclusion() {
    for (prior, lost, included, finalized) in [
        (false, false, false, true),
        (true, false, false, true),
        (false, true, false, true),
        (true, true, false, true),
        (false, true, false, false),
        (true, true, false, false),
        (false, true, true, true),
        (true, true, true, true),
        (false, true, true, false),
    ] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let control = harness::start_with_native(
                &context,
                CHAIN,
                "chain",
                harness::native(crate::protocol::deployments()),
                crate::protocol::Timing {
                    admission_offset: 100,
                    challenge_duration: 100,
                },
            )
            .await;
            let mut chain = client_with_holders(&context, &control, CHAIN);
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let setup = context.child("cached_context").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                if prior {
                    relay(&mut listener, &mut operator).await;
                }
                (listener, operator)
            });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            if prior {
                accepted(
                    agent
                        .pay(&context, &mut chain, address, &[(1, 7)])
                        .await
                        .unwrap(),
                );
            } else {
                assert_eq!(
                    agent.balance(&context, &mut chain, address).await.unwrap(),
                    INITIAL_BALANCE
                );
            }
            let (mut listener, mut operator) = setup.await.unwrap();
            let previous = if prior { 7 } else { 0 };
            assert_eq!(agent.store.debits_since(0).unwrap(), previous);
            assert_eq!(agent.cache.as_ref().unwrap().context, old);
            let expected = if lost {
                let stage = context.child("lost_receipt").spawn(move |_| async move {
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(request) =
                        operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                            .unwrap()
                    else {
                        panic!("expected send");
                    };
                    if included {
                        operator
                            .accept_send(request.authorization.clone(), request.entries)
                            .unwrap();
                    }
                    (listener, operator)
                });
                assert!(
                    agent
                        .pay(&context, &mut chain, address, &[(1, 3)])
                        .await
                        .is_err()
                );
                assert_eq!(agent.store.debits_since(0).unwrap(), previous);
                assert_eq!(agent.receipt_count(), u64::from(prior));
                let expected = agent
                    .pending_payment
                    .as_ref()
                    .unwrap()
                    .authorization
                    .encode();
                (listener, operator) = stage.await.unwrap();
                Some(expected)
            } else {
                None
            };
            if !prior && !included {
                operator.pay(2, 3, 1).unwrap();
            }
            let result = operator.complete_close(805).unwrap();
            if finalized {
                finalize(&control, &result).await;
            } else {
                applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
            }
            let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
            assert_eq!(admitted.finalized, finalized);
            let lookup = Holders::default()
                .committed_account_at(
                    &context,
                    &chain,
                    0,
                    &admitted.activity_range(),
                    &agent.account(),
                )
                .await
                .unwrap();
            let (_, activity) = lookup
                .resolve::<Sha256>(&admitted.activity_range(), &agent.account())
                .unwrap();
            if included {
                assert!(activity.unwrap().matches_outgoing(
                    &old,
                    agent.pending_payment.as_ref().unwrap().authorization.body()
                ));
            } else if !prior {
                assert!(activity.is_none_or(|activity| !activity.has_outgoing()));
            } else {
                let retained = agent.store.vector_state(&old).unwrap().unwrap();
                let vector = OutVector::new(0, agent.account(), retained.entries).unwrap();
                let body = VectorSendBody::new(
                    &old,
                    agent.account(),
                    retained.seq,
                    retained.cumulative_debit,
                    vector.root::<Sha256, Digest>().unwrap(),
                );
                assert!(activity.unwrap().matches_outgoing(&old, &body));
            }
            let successor = register(&control, &mut operator).await;
            assert_eq!(successor.epoch(), 1);
            let response_context = old.clone();
            let response = context
                .child("accepted_after_close")
                .spawn(move |_| async move {
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                            panic!("cached signing must submit directly");
                        };
                        if let Some(expected) = expected {
                            assert_eq!(request.authorization.encode(), expected);
                        }
                        assert_eq!(
                            request.authorization.body().anchor(),
                            response_context.anchor()
                        );
                        let prior_entries = if prior { bob_edge(7, 1) } else { Vec::new() };
                        let acceptance = issue_acceptance(
                            &Wallet::from_seed("operator", 1),
                            &prior_entries,
                            &request.authorization,
                            &request.entries,
                        );
                        acceptance.verify(&response_context).unwrap();
                        rpc::Response::Success {
                            body: accept_response(operator_rpc::AcceptedBatchResponse {
                                epoch: 0,
                                sequence: request.authorization.body().seq(),
                                total: 3,
                                acceptance,
                            }),
                        }
                    })
                    .await;
                    (listener, operator)
                });
            drop(agent);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            let outcome = agent.pay(&context, &mut chain, address, &[(1, 3)]).await;
            if included {
                assert_eq!(accepted(outcome.unwrap()).epoch, 0);
            } else {
                assert!(outcome.is_err());
            }
            assert!(agent.pending_payment.is_none());
            assert_eq!(
                agent.receipt_count(),
                u64::from(prior) + u64::from(included)
            );
            assert_eq!(
                agent.store.debits_since(0).unwrap(),
                previous + if included { 3 } else { 0 }
            );
            let vector = agent.store.vector_state(&old).unwrap();
            if prior || included {
                let vector = vector.unwrap();
                assert_eq!(vector.seq, u64::from(prior) + u64::from(included));
                assert_eq!(
                    vector.cumulative_debit,
                    previous + if included { 3 } else { 0 }
                );
            } else {
                assert!(vector.is_none());
            }
            assert_eq!(agent.cache.is_none(), finalized || !included);
            if finalized {
                let current = status(&control).await;
                let opening = Holders::default()
                    .validator_opening(&context, &mut chain, &agent.account(), &current)
                    .await
                    .unwrap();
                assert_eq!(
                    opening.balance.get(),
                    INITIAL_BALANCE - previous - if included { 3 } else { 0 }
                );
            }
            let (mut listener, mut operator) = response.await.unwrap();
            drop(agent);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(agent.pending_payment.is_none());
            assert_eq!(
                agent.store.debits_since(0).unwrap(),
                previous + if included { 3 } else { 0 }
            );
            if !included {
                let next = context
                    .child("honest_successor")
                    .spawn(move |_| async move {
                        relay(&mut listener, &mut operator).await;
                        relay(&mut listener, &mut operator).await;
                    });
                assert_eq!(
                    accepted(
                        agent
                            .pay(&context, &mut chain, address, &[(1, 3)])
                            .await
                            .unwrap()
                    )
                    .epoch,
                    1
                );
                assert_eq!(agent.store.debits_since(0).unwrap(), previous + 3);
                next.await.unwrap();
            }
        });
    }
}

#[test]
fn accepted_reply_cannot_complete_faulted_work_before_finalized_coverage() {
    for (admitted, invalidated) in [(false, false), (true, false), (true, true)] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let control = harness::start_with_native(&context, CHAIN, "chain", harness::native(crate::protocol::deployments()), crate::protocol::Timing { admission_offset: 100, challenge_duration: 100 }).await;
            let mut chain = client_with_holders(&context, &control, CHAIN);
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let challenged = if invalidated {
                let payment = register(&control, &mut operator).await;
                let receipt = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 5);
                operator.pay(2, 3, 1).unwrap();
                let result = operator.complete_close(806).unwrap();
                applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
                let lookup = operator.committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0).unwrap();
                Some((result, receipt, lookup))
            } else { None };
            let payment = register(&control, &mut operator).await;
            let mut listener = context.bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
            let address = listener.local_addr().unwrap();
            let stage = context.child("held_by_operator").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                let response = accept_and_drop(&mut listener, &mut operator).await;
                (listener, operator, response)
            });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(agent.pay(&context, &mut chain, address, &[(1, 7)]).await.is_err());
            let expected = agent.pending_payment.as_ref().unwrap().authorization.encode();
            let (mut listener, mut operator, response) = stage.await.unwrap();
            response.acceptance.verify(&payment).unwrap();
            let close = if admitted {
                let result = operator.complete_close(807).unwrap();
                applied(&control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
                Some(result)
            } else { None };
            if let Some((challenged, receipt, lookup)) = challenged {
                let evidence = commonware_clearing::bajillion::challenge::Challenge::HigherAckEntry {
                    entry: Box::new(commonware_clearing::bajillion::challenge::EntryWitness {
                        ack: commonware_clearing::bajillion::challenge::AckWitness::from_ack(&receipt.ack),
                        recipient: receipt.recipient.clone(), cumulative: receipt.cumulative,
                        count: receipt.count, opening: receipt.opening.clone(),
                    }), sender: Box::new(lookup),
                };
                control.submit(SettlementTx::Challenge(crate::chain::tx::ChallengeRequest {
                    deployment: deployment(), batch_id: challenged.header.batch_id::<Sha256>(), evidence: evidence.encode(),
                })).await;
                assert!(matches!(chain.fault(&context).await.unwrap(), Some(FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge { batch_id, .. })) if batch_id == challenged.header.batch_id::<Sha256>()));
                assert_eq!(payment.epoch(), 1);
            } else {
                if admitted { register(&control, &mut operator).await; }
                let deadline = registration_record(&control).await.admission_deadline;
                let height = control.advance(0).await;
                control.advance(deadline - height + 1).await;
            }
            assert!(status(&control).await.hard_faulted);
            assert!(status(&control).await.last_finalized.is_none());
            assert_eq!(chain.anchor(&context, payment.epoch()).await.unwrap(), Some(*payment.anchor()));
            let deferred = admitted && !invalidated;
            let served = response.clone();
            let first = context.child("faulted_acceptance").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(request) = request else { panic!("expected exact retry"); };
                    assert_eq!(request.authorization.encode(), expected);
                    rpc::Response::Success { body: accept_response(served) }
                }).await;
                listener
            });
            assert!(agent.resume_pending_payment(&context, &mut chain, address).await.is_err());
            assert_eq!(agent.pending_payment.is_some(), deferred);
            assert_eq!(agent.receipt_count(), 0);
            assert_eq!(agent.store.debits_since(0).unwrap(), 0);
            assert!(agent.store.vector_state(&payment).unwrap().is_none());
            let mut listener = first.await.unwrap();
            drop(agent);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert_eq!(agent.pending_payment.is_some(), deferred);
            assert_eq!(agent.store.debits_since(0).unwrap(), 0);
            if deferred {
                let expected = agent.pending_payment.as_ref().unwrap().authorization.encode();
                let close = close.unwrap();
                let height = control.advance(0).await;
                control.advance(close.context.epoch_context().challenge_deadline() - height + 1).await;
                assert!(chain.admitted(&context, payment.epoch()).await.unwrap().unwrap().finalized);
                let final_response = context.child("finalized_prefix_acceptance").spawn(move |_| async move {
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptSend(request) = request else { panic!("expected exact retry"); };
                        assert_eq!(request.authorization.encode(), expected);
                        rpc::Response::Success { body: accept_response(response) }
                    }).await;
                });
                assert_eq!(accepted(agent.resume_pending_payment(&context, &mut chain, address).await.unwrap().unwrap()).total, 7);
                assert_eq!(agent.receipt_count(), 1);
                assert_eq!(agent.store.debits_since(0).unwrap(), 7);
                assert!(agent.pending_payment.is_none());
                assert!(agent.cache.is_none());
                assert_eq!(agent.store.vector_state(&payment).unwrap().unwrap().cumulative_debit, 7);
                final_response.await.unwrap();
            }
        });
    }
}

#[test]
fn stale_heads_cannot_restore_a_concluded_signing_context() {
    for poll_balance in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let raw = operator.payment_head(&wallets()[0].public_key()).unwrap();
            let old_head = operator_rpc::PaymentHeadResponse {
                context: raw.context,
                balance: raw.balance,
                root: raw.root,
                opening: raw.opening,
            };
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let staging_address = listener.local_addr().unwrap();
            let staging = context
                .child("unanswered_old_send")
                .spawn(move |_| async move {
                    relay(&mut listener, &mut operator).await;
                    let (_, _sink, mut stream) = listener.accept().await.unwrap();
                    let operator_rpc::OperatorRequest::AcceptSend(_) =
                        operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                            .unwrap()
                    else {
                        panic!("expected the initial send");
                    };
                    operator
                });
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(
                agent
                    .pay(&context, &mut chain, staging_address, &[(1, 7)])
                    .await
                    .is_err()
            );
            let authorization = agent
                .pending_payment
                .as_ref()
                .unwrap()
                .authorization
                .clone();
            let old_id = Sha256::hash(&[authorization.body().encode().as_ref()]);
            let mut operator = staging.await.unwrap();
            operator.pay(2, 3, 1).unwrap();
            let close = operator.complete_close(820).unwrap();
            applied(&control, &SettlementTx::Admit(AdmitRequest::from(&close))).await;
            let admitted = chain.admitted(&context, 0).await.unwrap().unwrap();
            let activity = Holders::default()
                .committed_account_at(
                    &context,
                    &chain,
                    0,
                    &admitted.activity_range(),
                    &agent.account(),
                )
                .await
                .unwrap();
            assert!(
                activity
                    .resolve::<Sha256>(&admitted.activity_range(), &agent.account())
                    .unwrap()
                    .1
                    .is_none_or(|entry| !entry.has_outgoing())
            );
            assert!(
                agent
                    .resume_pending_payment(&context, &mut chain, UNREACHABLE)
                    .await
                    .is_err()
            );
            assert!(agent.pending_payment.is_none());
            assert!(agent.cache.is_none());
            assert_eq!(agent.store.debits_since(0).unwrap(), 0);
            let successor = register(&control, &mut operator).await;
            assert_eq!(successor.epoch(), 1);
            drop(agent);
            let mut chain = client_with_holders(&context, &control, CHAIN);
            let mut agent = Agent::open(database.path(), 0).unwrap();
            assert!(agent.pending_withdrawal_claim.is_none());
            let mut listener = context.bind(UNREACHABLE).await.unwrap();
            let successor_anchor = *successor.anchor();
            let server = context
                .child("repeated_stale_head")
                .spawn(move |_| async move {
                    for _ in 0..(1 + usize::from(poll_balance)) {
                        respond(&mut listener, |request| {
                            assert!(matches!(
                                request,
                                operator_rpc::OperatorRequest::PaymentHead(_)
                            ));
                            rpc::Response::Success {
                                body: old_head.encode(),
                            }
                        })
                        .await;
                    }
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptSend(send) = &request else {
                            panic!("expected the successor send");
                        };
                        assert_eq!(
                            send.authorization.body().epoch(),
                            1,
                            "a retired context cannot stage a fresh send"
                        );
                        assert_eq!(send.authorization.body().anchor(), &successor_anchor);
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                });
            if poll_balance {
                assert_eq!(
                    agent
                        .balance(&context, &mut chain, UNREACHABLE)
                        .await
                        .unwrap(),
                    INITIAL_BALANCE
                );
                assert!(
                    agent.cache.is_none(),
                    "a retired head must not repopulate the cache"
                );
            }
            let receipt = accepted(
                agent
                    .pay(&context, &mut chain, UNREACHABLE, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(receipt.epoch, 1);
            assert!(agent.cache.is_some());
            assert!(agent.pending_withdrawal_claim.is_none());
            assert!(agent.pending_payment.is_none());
            agent.ensure_store_usable().unwrap();
            assert_eq!(agent.receipt_count(), 1);
            assert_eq!(agent.store.debits_since(0).unwrap(), 7);
            assert!(agent.store.vector_state(&old).unwrap().is_none());
            assert_eq!(
                agent
                    .store
                    .vector_state(&successor)
                    .unwrap()
                    .unwrap()
                    .cumulative_debit,
                7
            );
            drop(agent);
            let connection = rusqlite::Connection::open_with_flags(
                database.path(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM agent_payments WHERE id = ?1",
                        [old_id.as_ref()],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                1
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM agent_payments", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                2
            );
            drop(connection);
            let agent = Agent::open(database.path(), 0).unwrap();
            assert_eq!(agent.store.debits_since(0).unwrap(), 7);
            assert_eq!(agent.receipt_count(), 1);
            server.await.unwrap();
        });
    }
}

#[test]
fn skipped_incoming_rows_share_one_durable_cursor_write() {
    for unresolved_tail in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let payment = register(&control, &mut operator).await;
            let receipt = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 5);
            let mut listener = context.bind(UNREACHABLE).await.unwrap();
            let retained = receipt.clone();
            let first = context.child("initial_incoming_credit").spawn(move |_| async move {
                respond(&mut listener, |_| rpc::Response::Success { body: incoming_response(&[(retained, 1)]).encode() }).await;
                listener
            });
            let mut receiver = Agent::open(database.path(), 1).unwrap();
            receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await.unwrap();
            let mut listener = first.await.unwrap();
            assert_eq!(receiver.incoming(), IncomingSummary { total: 5, count: 1, cursor: 1 });
            let mut page = vec![(receipt.clone(), 2), (receipt.clone(), 3), (receipt, 4)];
            if unresolved_tail {
                let future = PaymentContext::new(Sha256::hash(&[b"not-yet-registered"]), 99, operator_key());
                page.push((issued_receipt(&future, &wallets()[2], &wallets()[1].public_key(), 1), 5));
            }
            let server = context.child("skipped_incoming_prefix").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::IncomingPayments(request) if request.cursor == 1));
                    rpc::Response::Success { body: incoming_response(&page).encode() }
                }).await;
            });
            let changes = receiver.store.total_changes();
            let outcome = receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await;
            assert_eq!(outcome.is_err(), unresolved_tail);
            assert_eq!(receiver.store.total_changes() - changes, 1, "a skipped prefix needs one cursor transaction");
            assert_eq!(receiver.incoming(), IncomingSummary { total: 5, count: 1, cursor: 4 });
            assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
            receiver.ensure_store_usable().unwrap();
            drop(receiver);
            let receiver = Agent::open(database.path(), 1).unwrap();
            assert_eq!(receiver.incoming(), IncomingSummary { total: 5, count: 1, cursor: 4 });
            server.await.unwrap();
        });
    }
}

fn receipt_challenge(
    batch_id: BatchId<Digest>,
    receipt: &Receipt,
    lookup: HigherEntryLookup<Key, Digest>,
) -> SettlementTx {
    SettlementTx::Challenge(ChallengeRequest {
        deployment: deployment(),
        batch_id,
        evidence: Challenge::HigherAckEntry {
            entry: Box::new(EntryWitness {
                ack: AckWitness::from_ack(&receipt.ack),
                recipient: receipt.recipient.clone(),
                cumulative: receipt.cumulative,
                count: receipt.count,
                opening: receipt.opening.clone(),
            }),
            sender: Box::new(lookup),
        }
        .encode(),
    })
}

#[test]
fn accepted_activity_is_reclassified_after_its_evidence_await() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let database = TempDatabase::new();
        let control = harness::start_with_native(&context, CHAIN, "chain", harness::native(crate::protocol::deployments()), crate::protocol::Timing { admission_offset: 100, challenge_duration: 100 }).await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let first = register(&control, &mut operator).await;
        let omitted = issued_receipt(&first, &wallets()[2], &wallets()[3].public_key(), 5);
        operator.pay(1, 3, 1).unwrap();
        let predecessor = operator.complete_close(821).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&predecessor))).await;
        let omission = operator.committed_entry(&wallets()[2].public_key(), &wallets()[3].public_key(), 0).unwrap();
        assert_eq!(omission.resolve::<Sha256>(&activity_range(&predecessor), &wallets()[2].public_key(), &wallets()[3].public_key()).unwrap(), (0, 0));
        let payment = register(&control, &mut operator).await;
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let staging = context.child("lost_included_receipt").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let response = accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator, response)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert!(agent.pay(&context, &mut chain, UNREACHABLE, &[(1, 7)]).await.is_err());
        let expected = agent.pending_payment.as_ref().unwrap().authorization.encode();
        let (mut listener, mut operator, response) = staging.await.unwrap();
        let close = operator.complete_close(822).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&close))).await;
        let admitted = chain.admitted(&context, 1).await.unwrap().unwrap();
        assert!(!admitted.finalized);
        let account = agent.account();
        let request = EvidenceRequest::new(deployment(), EvidenceLookup::Account { epoch: 1, range: admitted.activity_range(), account: account.clone() });
        let saved = control.evidence(request.clone()).await;
        let EvidenceResponse::Served(Evidence::Account(ref lookup)) = saved else { panic!("included account evidence is available"); };
        assert!(lookup.resolve::<Sha256>(&admitted.activity_range(), &account).unwrap().1.unwrap().matches_outgoing(&payment, agent.pending_payment.as_ref().unwrap().authorization.body()));
        let mut holder = context.bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let holder_address = holder.local_addr().unwrap();
        let (entered, blocked) = futures::channel::oneshot::channel();
        let (release, resume) = futures::channel::oneshot::channel();
        let holder_server = context.child("gated_account_evidence").spawn(move |_| async move {
            let (_, mut sink, mut stream) = holder.accept().await.unwrap();
            let incoming = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(incoming.method, METHOD_EVIDENCE);
            assert_eq!(EvidenceRequest::decode(incoming.body).unwrap(), request);
            entered.send(()).unwrap();
            resume.await.unwrap();
            rpc::send_response(&mut sink, &rpc::Response::Success { body: saved.encode() }).await.unwrap();
        });
        let operator_server = context.child("exact_delayed_acceptance").spawn(move |_| async move {
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(send) = request else { panic!("expected exact retry"); };
                assert_eq!(send.authorization.encode(), expected);
                rpc::Response::Success { body: accept_response(response) }
            }).await;
        });
        let mut chain = client_with_holders(&context, &control, holder_address);
        let paying = context.child("resolve_while_faulting").spawn(move |ctx| async move {
            let result = agent.resume_pending_payment(&ctx, &mut chain, UNREACHABLE).await;
            (agent, result)
        });
        blocked.await.unwrap();
        assert!(!status(&control).await.hard_faulted);
        control.submit(receipt_challenge(predecessor.header.batch_id::<Sha256>(), &omitted, omission)).await;
        assert!(matches!(control.record(fault_key(&deployment())).await, Some(Record::Fault(FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge { batch_id, .. }))) if batch_id == predecessor.header.batch_id::<Sha256>()));
        release.send(()).unwrap();
        let (agent, result) = paying.await.unwrap();
        assert!(result.is_err());
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.receipt_count(), 0);
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
        assert!(agent.store.vector_state(&payment).unwrap().is_none());
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert!(agent.pending_payment.is_none());
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
        holder_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

#[test]
fn hidden_later_challenge_defers_receipts_until_terminal_settlement() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let payer_database = TempDatabase::new();
        let receiver_database = TempDatabase::new();
        let control = harness::start_with_native(&context, CHAIN, "chain", harness::native(crate::protocol::deployments()), crate::protocol::Timing { admission_offset: 100, challenge_duration: 100 }).await;
        let mut chain = client_with_holders(&context, &control, CHAIN);
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let payment = register(&control, &mut operator).await;
        let omitted = issued_receipt(&payment, &wallets()[2], &wallets()[3].public_key(), 5);
        let incoming = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 7);
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let staging = context.child("included_before_first_fault").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let accepted = accept_and_drop(&mut listener, &mut operator).await;
            (listener, operator, accepted)
        });
        let mut payer = Agent::open(payer_database.path(), 0).unwrap();
        assert!(payer.pay(&context, &mut chain, UNREACHABLE, &[(1, 7)]).await.is_err());
        let expected = payer.pending_payment.as_ref().unwrap().authorization.encode();
        let (mut listener, mut operator, accepted) = staging.await.unwrap();
        let close = operator.complete_close(823).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&close))).await;
        let omission = operator.committed_entry(&wallets()[2].public_key(), &wallets()[3].public_key(), 0).unwrap();
        assert_eq!(omission.resolve::<Sha256>(&activity_range(&close), &wallets()[2].public_key(), &wallets()[3].public_key()).unwrap(), (0, 0));
        let covered = operator.committed_entry(&wallets()[0].public_key(), &wallets()[1].public_key(), 0).unwrap();
        assert_eq!(covered.resolve::<Sha256>(&activity_range(&close), &wallets()[0].public_key(), &wallets()[1].public_key()).unwrap(), (7, 1));
        register(&control, &mut operator).await;
        let deadline = registration_record(&control).await.admission_deadline;
        let height = control.advance(0).await;
        control.advance(deadline - height + 1).await;
        assert!(matches!(chain.fault(&context).await.unwrap(), Some(FaultRecord::Faulted(HardFaultReasonResponse::ExpiredRegistration { .. }))));
        assert!(!chain.admitted(&context, 0).await.unwrap().unwrap().finalized);
        control.submit(receipt_challenge(close.header.batch_id::<Sha256>(), &omitted, omission)).await;
        assert!(matches!(chain.fault(&context).await.unwrap(), Some(FaultRecord::Faulted(HardFaultReasonResponse::ExpiredRegistration { .. }))));
        let height = control.advance(0).await;
        control.advance(close.context.epoch_context().challenge_deadline() - height + 1).await;
        assert!(status(&control).await.last_finalized.is_none(), "a surviving clean close would have finalized");
        assert!(!chain.admitted(&context, 0).await.unwrap().unwrap().finalized);
        let expected_retry = expected.clone();
        let server = context.child("hidden_fault_receipts").spawn(move |_| async move {
            for _ in 0..2 {
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::IncomingPayments(request) if request.cursor == 0));
                    rpc::Response::Success { body: incoming_response(&[(incoming.clone(), 1)]).encode() }
                }).await;
                respond(&mut listener, |request| {
                    let operator_rpc::OperatorRequest::AcceptSend(send) = request else { panic!("expected pending retry"); };
                    assert_eq!(send.authorization.encode(), expected_retry);
                    rpc::Response::Success { body: accept_response(accepted.clone()) }
                }).await;
            }
        });
        let mut receiver = Agent::open(receiver_database.path(), 1).unwrap();
        assert!(receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await.is_err());
        assert!(payer.resume_pending_payment(&context, &mut chain, UNREACHABLE).await.is_err());
        assert_eq!(receiver.incoming(), IncomingSummary::default());
        assert_eq!(receiver.store.credits_since(0).unwrap(), 0);
        assert_eq!(payer.pending_payment.as_ref().unwrap().authorization.encode(), expected);
        assert_eq!(payer.receipt_count(), 0);
        assert_eq!(payer.store.debits_since(0).unwrap(), 0);
        drop(receiver);
        drop(payer);
        let mut receiver = Agent::open(receiver_database.path(), 1).unwrap();
        let mut payer = Agent::open(payer_database.path(), 0).unwrap();
        assert_eq!(receiver.incoming(), IncomingSummary::default());
        assert_eq!(payer.pending_payment.as_ref().unwrap().authorization.encode(), expected);
        control.submit(SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest { deployment: deployment() })).await;
        let Some(FaultRecord::Settling(settlement)) = chain.fault(&context).await.unwrap() else { panic!("terminal boundary is certified"); };
        assert_eq!(settlement.invalid_from, Some(close.header.batch_id::<Sha256>()));
        receiver.intake_incoming(&context, &mut chain, UNREACHABLE).await.unwrap();
        assert!(payer.resume_pending_payment(&context, &mut chain, UNREACHABLE).await.is_err());
        assert_eq!(receiver.incoming(), IncomingSummary { total: 0, count: 0, cursor: 1 });
        assert!(payer.pending_payment.is_none());
        assert_eq!(payer.receipt_count(), 0);
        assert_eq!(payer.store.debits_since(0).unwrap(), 0);
        assert!(payer.store.vector_state(&payment).unwrap().is_none());
        server.await.unwrap();
    });
}

#[test]
fn finalized_signed_incoming_receipt_uses_retained_admitted_evidence() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let payment = register(&control, &mut operator).await;
        let receipt = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 7);
        operator.pay(0, 1, 7).unwrap();
        let finalized = operator.complete_close(824).unwrap();
        finalize(&control, &finalized).await;
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let server = context
            .child("finalized_receipt_page")
            .spawn(move |_| async move {
                respond(&mut listener, |_| rpc::Response::Success {
                    body: incoming_response(&[(receipt, 1)]).encode(),
                })
                .await;
            });
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        receiver
            .intake_incoming(&context, &mut chain, UNREACHABLE)
            .await
            .unwrap();
        assert_eq!(
            receiver.incoming(),
            IncomingSummary {
                total: 7,
                count: 1,
                cursor: 1
            }
        );
        server.await.unwrap();
    });
}

#[test]
fn live_incoming_credit_is_durable_before_the_next_evidence_await() {
    for cancel in [true, false] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let database = TempDatabase::new();
            let (control, _) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let finalized_receipt =
                issued_receipt(&old, &wallets()[0], &wallets()[1].public_key(), 7);
            operator.pay(0, 1, 7).unwrap();
            let finalized = operator.complete_close(824).unwrap();
            finalize(&control, &finalized).await;
            let live = register(&control, &mut operator).await;
            let live_receipt =
                issued_receipt(&live, &wallets()[0], &wallets()[1].public_key(), 5);
            operator.pay(2, 3, 1).unwrap();
            let unfinalized = operator.complete_close(825).unwrap();
            applied(
                &control,
                &SettlementTx::Admit(AdmitRequest::from(&unfinalized)),
            )
            .await;

            let mut incoming = context.bind(UNREACHABLE).await.unwrap();
            let incoming_server = context.child("live_then_finalized_page").spawn(move |_| async move {
                respond(&mut incoming, |_| rpc::Response::Success {
                    body: incoming_response(&[(live_receipt, 1), (finalized_receipt, 2)]).encode(),
                })
                .await;
            });
            let mut holder = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 9_852)))
                .await
                .unwrap();
            let holder_address = holder.local_addr().unwrap();
            let (entered, blocked) = futures::channel::oneshot::channel();
            let (release, resume) = futures::channel::oneshot::channel();
            let holder_server = context.child("blocked_finalized_entry").spawn(move |_| async move {
                let (_, mut sink, mut stream) = holder.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(request.method, METHOD_EVIDENCE);
                assert!(matches!(
                    EvidenceRequest::decode(request.body).unwrap().lookup,
                    EvidenceLookup::CommittedEntry { epoch: 0, .. }
                ));
                entered.send(()).unwrap();
                resume.await.unwrap();
                let _ = rpc::send_response(
                    &mut sink,
                    &rpc::error_response("committed entry unavailable".into()),
                )
                .await;
            });
            let mut chain = client_with_holders(&context, &control, holder_address);
            let mut receiver = Agent::open(database.path(), 1).unwrap();
            let mut intake = Box::pin(receiver.intake_incoming(&context, &mut chain, UNREACHABLE));
            commonware_macros::select! {
                result = &mut intake => panic!("intake stopped before the second-row gate: {result:?}"),
                result = blocked => result.unwrap(),
            }

            // Snapshot the quiescent database and WAL while intake remains blocked outside
            // SQLite. The copied wallet must observe the committed prefix before cancellation or
            // error handling can flush the original connection.
            let snapshot = TempDatabase::new();
            let mut source_db = File::open(database.path()).unwrap();
            let mut target_db = File::create(snapshot.path()).unwrap();
            io::copy(&mut source_db, &mut target_db).unwrap();
            drop(target_db);
            let source_wal_path = database.path().with_extension("sqlite-wal");
            let snapshot_wal_path = snapshot.path().with_extension("sqlite-wal");
            let mut source_wal = File::open(source_wal_path).unwrap();
            let mut target_wal = File::create(snapshot_wal_path).unwrap();
            io::copy(&mut source_wal, &mut target_wal).unwrap();
            drop(target_wal);
            let snapshot_receiver = Agent::open(snapshot.path(), 1).unwrap();
            assert_eq!(
                snapshot_receiver.incoming(),
                IncomingSummary {
                    total: 5,
                    count: 1,
                    cursor: 1
                }
            );
            assert_eq!(snapshot_receiver.store.credits_since(0).unwrap(), 5);
            drop(snapshot_receiver);

            if cancel {
                drop(intake);
                drop(receiver);
                drop(source_db);
                drop(source_wal);
                let receiver = Agent::open(database.path(), 1).unwrap();
                assert_eq!(
                    receiver.incoming(),
                    IncomingSummary {
                        total: 5,
                        count: 1,
                        cursor: 1
                    }
                );
                assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
                drop(receiver);
                release.send(()).unwrap();
            } else {
                release.send(()).unwrap();
                assert!(intake.await.is_err());
                assert_eq!(
                    receiver.incoming(),
                    IncomingSummary {
                        total: 5,
                        count: 1,
                        cursor: 1
                    }
                );
                assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
                drop(receiver);
                drop(source_db);
                drop(source_wal);
                let receiver = Agent::open(database.path(), 1).unwrap();
                assert_eq!(
                    receiver.incoming(),
                    IncomingSummary {
                        total: 5,
                        count: 1,
                        cursor: 1
                    }
                );
                assert_eq!(receiver.store.credits_since(0).unwrap(), 5);
            }
            holder_server.await.unwrap();
            incoming_server.await.unwrap();
        });
    }
}

#[test]
fn clean_prefix_finalizing_during_fault_read_remains_creditable() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let database = TempDatabase::new();
        let control = harness::start_with_native(&context, CHAIN, "chain", harness::native(crate::protocol::deployments()), crate::protocol::Timing { admission_offset: 100, challenge_duration: 100 }).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let payment = register(&control, &mut operator).await;
        let receipt = issued_receipt(&payment, &wallets()[0], &wallets()[1].public_key(), 7);
        operator.pay(0, 1, 7).unwrap();
        let close = operator.complete_close(826).unwrap();
        applied(&control, &SettlementTx::Admit(AdmitRequest::from(&close))).await;
        register(&control, &mut operator).await;
        let deadline = registration_record(&control).await.admission_deadline;
        let height = control.advance(0).await;
        control.advance(deadline - height + 1).await;
        assert!(status(&control).await.hard_faulted);
        assert!(status(&control).await.last_finalized.is_none());
        let mut listener = context.bind(UNREACHABLE).await.unwrap();
        let operator_server = context.child("clean_faulted_receipt").spawn(move |_| async move {
            respond(&mut listener, |_| rpc::Response::Success { body: incoming_response(&[(receipt, 1)]).encode() }).await;
        });
        let mut proxy = context.bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let (entered, blocked) = futures::channel::oneshot::channel();
        let (release, resume) = futures::channel::oneshot::channel();
        let source = control.clone();
        let query_server = context.child("fault_read_crosses_settling").spawn(move |_| async move {
            let mut gate = Some((entered, resume));
            loop {
                let (_, mut sink, mut stream) = proxy.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(request.method, crate::chain::query::METHOD_READ);
                let request = ReadRequest::decode(request.body).unwrap();
                if matches!(request.lookup, Lookup::Fault) && let Some((entered, resume)) = gate.take() {
                    entered.send(()).unwrap();
                    resume.await.unwrap();
                }
                let response = source.read(request).await;
                rpc::send_response(&mut sink, &rpc::Response::Success { body: response.encode() }).await.unwrap();
            }
        });
        let mut genesis = control.identity().clone();
        for validator in &mut genesis.validators { validator.query = CHAIN; }
        let mut chain = Client::new(&genesis, deployment(), vec![proxy_address], context.child("crossing_client")).unwrap();
        let mut receiver = Agent::open(database.path(), 1).unwrap();
        let receiving = context.child("receive_across_terminal_boundary").spawn(move |ctx| async move {
            let result = receiver.intake_incoming(&ctx, &mut chain, UNREACHABLE).await;
            (receiver, result)
        });
        blocked.await.unwrap();
        assert!(matches!(control.record(admitted_key(&deployment(), 0)).await, Some(Record::Admitted(record)) if !record.finalized));
        let height = control.advance(0).await;
        control.advance(close.context.epoch_context().challenge_deadline() - height + 1).await;
        assert_eq!(status(&control).await.last_finalized, Some(0));
        control.submit(SettlementTx::BeginHardFaultSettlement(BeginHardFaultSettlementRequest { deployment: deployment() })).await;
        assert!(matches!(control.record(fault_key(&deployment())).await, Some(Record::Fault(FaultRecord::Settling(snapshot))) if snapshot.invalid_from.is_none()));
        release.send(()).unwrap();
        let (receiver, result) = receiving.await.unwrap();
        result.unwrap();
        assert_eq!(receiver.incoming(), IncomingSummary { total: 7, count: 1, cursor: 1 });
        assert_eq!(receiver.store.credits_since(0).unwrap(), 7);
        drop(receiver);
        let receiver = Agent::open(database.path(), 1).unwrap();
        assert_eq!(receiver.incoming(), IncomingSummary { total: 7, count: 1, cursor: 1 });
        query_server.abort();
        operator_server.await.unwrap();
    });
}
