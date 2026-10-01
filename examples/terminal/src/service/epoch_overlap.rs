//! Payment and withdrawal admission during successor registration and an unfinished close.

use super::*;
use crate::{
    agent::PaymentOutcome,
    chain::{
        harness,
        state::{Record, admitted_key, registration_key},
        tx::{AdmitRequest, QueueWithdrawalRequest},
    },
    operator::Stage,
    protocol::{SettlementResult, deployment},
};
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction},
    vector::{OutEntry, OutVector},
};
use commonware_runtime::deterministic;
use commonware_utils::channel::oneshot;
use std::{
    num::NonZeroU64,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::SyncSender,
    },
};

const CHAIN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_703);
/// An address nothing binds, so the wallet reads its balance from the validators.
const UNREACHABLE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_704);
const TIMING: Timing = Timing {
    admission_offset: 1_000,
    challenge_duration: 8,
};

fn client(context: &deterministic::Context, control: &harness::Control) -> Client {
    Client::new(
        control.identity(),
        deployment(),
        vec![CHAIN],
        context.child("chain_rng"),
    )
    .unwrap()
}

/// The certified native balance of `account`.
async fn native(
    context: &deterministic::Context,
    chain: &mut Client,
    account: crate::protocol::Key,
) -> u64 {
    let chain_id = chain.genesis().native.chain_id();
    chain
        .native_balance(context, chain_id, account)
        .await
        .unwrap()
}

struct ReleaseClose(Option<SyncSender<()>>);

impl ReleaseClose {
    fn release(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for ReleaseClose {
    fn drop(&mut self) {
        self.release();
    }
}

#[test]
fn successor_receipt_precedes_predecessor_construction_and_admission() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        let control = harness::start_with_native(
            &context,
            CHAIN,
            "epoch_overlap",
            harness::native(crate::protocol::deployments()),
            TIMING,
        )
        .await;
        let operator = Arc::new(Mutex::new(
            Operator::open(std::path::Path::new(":memory:"), NonZeroUsize::MIN).unwrap(),
        ));
        let mut alice = Agent::new(0).unwrap();
        let mut bob = Agent::new(1).unwrap();
        let mut alice_chain = client(&context, &control);
        let mut bob_chain = client(&context, &control);

        let listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let strategy = operator.lock().payment_strategy();
        let (payment_sender, payment_worker) = payments::start(
            context.child("payments"),
            client(&context, &control),
            operator.clone(),
            strategy,
            TIMING,
        );
        let server = context.child("operator_rpc").spawn({
            let operator = operator.clone();
            let control = control.clone();
            move |server_context| async move {
                let request_context = server_context.child("request");
                payments::serve_connections(server_context, listener, move |request| {
                    let operator = operator.clone();
                    let mut chain = client(&request_context, &control);
                    let payment_sender = payment_sender.clone();
                    let context = request_context.child("connection");
                    async move {
                        match operator_rpc::decode_request(request) {
                            Ok(operator_rpc::OperatorRequest::AcceptSend(request)) => {
                                payments::submit(
                                    &payment_sender,
                                    operator_rpc::AcceptSendsRequest {
                                        sends: vec![request],
                                    },
                                    payments::ResponseKind::Single,
                                )
                                .await
                            }
                            Ok(request) => {
                                match prepare_request(
                                    &context,
                                    &mut chain,
                                    &operator,
                                    &request,
                                    TIMING,
                                )
                                .await
                                {
                                    Ok(Some(response)) => response,
                                    Ok(None) => {
                                        operator_rpc::handle_decoded(&mut operator.lock(), request)
                                    }
                                    Err(error) => rpc::error_response(format!("{error:#}")),
                                }
                            }
                            Err(error) => rpc::error_response(format!("{error:#}")),
                        }
                    }
                })
                .await;
            }
        });

        let first = alice
            .pay(&context, &mut alice_chain, address, &[(1, 2)])
            .await
            .unwrap();
        assert!(matches!(first, PaymentOutcome::Accepted(ref accepted) if accepted.epoch == 0));
        let registration = alice_chain.registration(&context).await.unwrap().unwrap();
        assert_eq!(registration.epoch, 0);
        assert!(registration.admitted.is_none());

        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        assert_eq!(operator_rpc::start_close(&context, address, 0).await.unwrap().epoch, 0);
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(operator.lock().status().unwrap().epoch, 1);
        assert!(alice_chain.admitted(&context, 0).await.unwrap().is_none());

        // The predecessor worker is still blocked before preparation. The
        // successor's first receipt must be valid under a certified epoch-1 anchor.
        let second = commonware_macros::select! {
            result = bob.pay(&context, &mut bob_chain, address, &[(0, 1)]) => {
                result.unwrap_or_else(|error| panic!("successor wallet payment failed before predecessor admission: {error:#}"))
            },
            _ = context.sleep(Duration::from_secs(5)) => {
                let record = control.record(registration_key(&deployment(), 1)).await;
                assert!(matches!(record, Some(Record::Registration(ref registered)) if registered.epoch == 1),
                    "successor registration is still blocked before predecessor admission: {record:?}");
                panic!("successor wallet payment waited despite certified successor registration")
            },
        };
        let PaymentOutcome::Accepted(second) = second else {
            panic!("successor wallet has no authenticated receipt: {second:?}");
        };
        assert_eq!(second.epoch, 1);
        assert_eq!(bob.receipt_count(), 1);
        let registration = bob_chain.registration(&context).await.unwrap().unwrap();
        assert_eq!(registration.epoch, 1);
        assert_eq!(registration.admitted, None);
        assert_eq!(second.acceptance.ack.body().anchor(), &registration.anchor);
        assert!(bob_chain.admitted(&context, 0).await.unwrap().is_none());
        assert!(control.record(admitted_key(&deployment(), 0)).await.is_none());

        release.release();
        server.abort();
        payment_worker.abort();
        let _ = server.await;
        let _ = payment_worker.await;
    });
}

/// Starts the harness chain under the overlap timing policy.
async fn chain(context: &deterministic::Context) -> harness::Control {
    harness::start_with_native(
        context,
        CHAIN,
        "epoch_overlap",
        harness::native(crate::protocol::deployments()),
        TIMING,
    )
    .await
}

/// Opens an in-memory operator shared by the service tasks and the test.
fn operator() -> Arc<Mutex<Operator>> {
    Arc::new(Mutex::new(
        Operator::open(std::path::Path::new(":memory:"), NonZeroUsize::MIN).unwrap(),
    ))
}

/// Unwraps a payment concluded with verified receipts.
fn accepted(outcome: PaymentOutcome) -> operator_rpc::AcceptedBatchResponse {
    match outcome {
        PaymentOutcome::Accepted(accepted) => *accepted,
        outcome => panic!("the payment has no authenticated receipt: {outcome:?}"),
    }
}

#[derive(Default)]
struct RegistrationGate {
    hide_heads: bool,
    publish: bool,
    readback: bool,
    publishing: Option<oneshot::Sender<()>>,
    reading: Option<oneshot::Sender<()>>,
}

struct HeldRegistration {
    inner: Client,
    gate: Option<Arc<Mutex<RegistrationGate>>>,
}

impl HeldRegistration {
    async fn hold(&self, publication: bool) {
        let Some(gate) = &self.gate else { return };
        loop {
            {
                let mut gate = gate.lock();
                let (held, entered) = if publication {
                    (gate.publish, gate.publishing.take())
                } else {
                    (gate.readback, gate.reading.take())
                };
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                if !held {
                    return;
                }
            }
            commonware_runtime::reschedule().await;
        }
    }

    async fn readback(&self, verified: &crate::chain::light::Verified) {
        if matches!(&verified.record, Some(Record::Registration(record)) if record.epoch == 1) {
            self.hold(false).await;
        }
    }
}

impl Chain for HeldRegistration {
    fn deployment(&self) -> Digest {
        self.inner.deployment()
    }

    fn holders(&self) -> Result<Vec<SocketAddr>> {
        self.inner.holders()
    }

    async fn inbox<E: Env>(
        &mut self,
        ctx: &E,
        indices: std::ops::Range<u64>,
    ) -> Result<Vec<crate::chain::state::Intake>> {
        self.inner.inbox(ctx, indices).await
    }

    async fn read<E: Env>(
        &mut self,
        ctx: &E,
        request: &crate::chain::query::ReadRequest,
    ) -> Result<crate::chain::light::Verified> {
        let verified = self.inner.read(ctx, request).await?;
        self.readback(&verified).await;
        Ok(verified)
    }

    async fn recent<E: Env>(
        &mut self,
        ctx: &E,
        request: &crate::chain::query::ReadRequest,
    ) -> Result<crate::chain::light::Verified> {
        let verified = self.inner.recent(ctx, request).await?;
        self.readback(&verified).await;
        Ok(verified)
    }

    async fn submit<E: Env>(
        &mut self,
        ctx: &E,
        tx: &SettlementTx,
    ) -> Result<crate::chain::ingress::Submission> {
        if matches!(tx, SettlementTx::RegisterEpoch(request) if request.epoch == 1) {
            self.hold(true).await;
        }
        self.inner.submit(ctx, tx).await
    }
}

/// The operator keeps receipting in the registered epoch while its successor registration is
/// submitted and read back, and switches to the successor anchor only at the certified handoff.
#[test]
fn current_receipts_continue_until_successor_registration_is_certified() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        // Alice pays in epoch 0 while successor submission and read-back are both held.
        let control = chain(&context).await;
        let operator = operator();
        let (publishing, published) = oneshot::channel();
        let (reading, read) = oneshot::channel();
        let gate = Arc::new(Mutex::new(RegistrationGate {
            publish: true,
            readback: true,
            hide_heads: false,
            publishing: Some(publishing),
            reading: Some(reading),
        }));
        let service =
            Service::start_held(&context, &control, &operator, Some(gate.clone()), 0).await;
        let mut alice = Agent::new(0).unwrap();
        let mut bob = Agent::new(1).unwrap();
        let mut alice_chain = client(&context, &control);
        let mut bob_chain = client(&context, &control);
        assert_eq!(
            accepted(
                alice
                    .pay(&context, &mut alice_chain, service.address, &[(1, 2)])
                    .await
                    .unwrap(),
            )
            .epoch,
            0
        );

        // A close request starts successor registration, and payments continue in epoch 0 while
        // its submission is held.
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        let closing = context.child("manual_close").spawn({
            let address = service.address;
            let mut trigger_chain = client(&context, &control);
            move |context| async move {
                let closed = operator_rpc::start_close(&context, address, 0).await?;
                let mut trigger = Agent::new(2)?;
                trigger
                    .pay(&context, &mut trigger_chain, address, &[(1, 1)])
                    .await?;
                Ok::<_, anyhow::Error>(closed)
            }
        });
        let driver = start_close_driver(
            &context,
            HeldRegistration {
                inner: client(&context, &control),
                gate: Some(gate.clone()),
            },
            operator.clone(),
            TIMING,
        );
        published.await.unwrap();
        assert!(
            control
                .record(registration_key(&deployment(), 1))
                .await
                .is_none()
        );

        let payment = alice.pay(&context, &mut alice_chain, service.address, &[(1, 3)]);
        let during = commonware_macros::select! {
            result = payment => Some(result),
            _ = context.sleep(Duration::from_secs(1)) => None,
        };
        if during.is_none() {
            gate.lock().publish = false;
            gate.lock().readback = false;
            release.release();
            closing.abort();
            driver.abort();
            let _ = closing.await;
            let _ = driver.await;
            service.stop().await;
            panic!("current-epoch payment waited for pending successor registration");
        }
        let during = accepted(during.unwrap().unwrap());
        assert_eq!(during.epoch, 0);
        assert_eq!(operator.lock().status().unwrap().epoch, 0);

        // The registration lands but its read-back is held, so the operator head stays in epoch 0.
        gate.lock().publish = false;
        read.await.unwrap();

        let registered = bob_chain
            .registration_at(&context, 1)
            .await
            .unwrap()
            .unwrap();
        let visible = accepted(
            bob.pay(&context, &mut bob_chain, service.address, &[(0, 1)])
                .await
                .unwrap(),
        );
        assert_eq!(
            visible.epoch, 0,
            "publication alone must not switch the operator head"
        );
        let last = accepted(
            alice
                .pay(&context, &mut alice_chain, service.address, &[(1, 4)])
                .await
                .unwrap(),
        );
        assert_eq!(last.epoch, 0);

        // The certified handoff moves Alice to the successor, bound to her final epoch-0 vector.
        let before = service.sends.lock().len();
        gate.lock().readback = false;
        assert_eq!(closing.await.unwrap().unwrap().epoch, 0);
        driver.abort();
        let _ = driver.await;
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let successor = accepted(
            alice
                .pay(&context, &mut alice_chain, service.address, &[(1, 5)])
                .await
                .unwrap(),
        );
        assert_eq!(successor.epoch, 1);
        assert_eq!(successor.acceptance.ack.body().anchor(), &registered.anchor);
        let sent = service.sends.lock()[before..]
            .iter()
            .filter(|send| {
                send.authorization.body().payer() == &crate::protocol::wallets()[0].public_key()
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(sent.len(), 2);
        let predecessor = OutVector::new(
            0,
            sent[1].authorization.body().payer().clone(),
            vec![OutEntry {
                recipient: crate::protocol::wallets()[1].public_key(),
                cumulative: 9,
                count: 3,
            }],
        )
        .unwrap()
        .root::<Sha256, Digest>()
        .unwrap();
        assert_eq!(sent[1].authorization.predecessor(), predecessor);
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        release.release();
        operator.lock().wait_for_closes().unwrap();
        service.stop().await;
    });
}

/// A successor registration cancelled after submission stays discoverable. A wallet that finds
/// its anchor retries the same send until the next close driver completes the handoff, while
/// payments continue in the registered epoch.
#[test]
fn discoverable_successor_retries_after_cancelled_registration_without_stopping_current_payments() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        // Alice pays in epoch 0, then successor registration is cancelled during read-back.
        let control = chain(&context).await;
        let operator = operator();
        let (reading, read) = oneshot::channel();
        let gate = Arc::new(Mutex::new(RegistrationGate {
            readback: true,
            reading: Some(reading),
            ..RegistrationGate::default()
        }));
        let service =
            Service::start_held(&context, &control, &operator, Some(gate.clone()), 0).await;
        let mut alice = Agent::new(0).unwrap();
        let mut alice_chain = client(&context, &control);
        assert_eq!(
            accepted(
                alice
                    .pay(&context, &mut alice_chain, service.address, &[(1, 1)])
                    .await
                    .unwrap(),
            )
            .epoch,
            0
        );
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        let closing = context.child("cancelled_close").spawn({
            let operator = operator.clone();
            let mut chain = HeldRegistration {
                inner: client(&context, &control),
                gate: Some(gate.clone()),
            };
            move |context| async move {
                register_successor(&context, &mut chain, &operator, 0, TIMING)
                    .await
                    .map(|started| started.epoch)
            }
        });
        read.await.unwrap();
        closing.abort();
        let _ = closing.await;
        assert!(operator.lock().successor_pending().unwrap());
        assert_eq!(operator.lock().status().unwrap().epoch, 0);

        // A cold wallet signs under the discoverable successor and waits without a result.
        gate.lock().hide_heads = true;
        let mut future = context.child("future_wallet").spawn({
            let address = service.address;
            let mut chain = client(&context, &control);
            move |context| async move {
                let mut wallet = Agent::new(2).unwrap();
                let receipt = accepted(
                    wallet
                        .pay(&context, &mut chain, address, &[(1, 1)])
                        .await
                        .unwrap(),
                );
                (receipt, wallet.receipt_count())
            }
        });
        let payer = crate::protocol::wallets()[2].public_key();
        let pending = loop {
            if let Some(send) = service
                .sends
                .lock()
                .iter()
                .find(|send| send.authorization.body().payer() == &payer)
                .cloned()
            {
                break send;
            }
            commonware_runtime::reschedule().await;
        };
        assert_eq!(pending.authorization.body().epoch(), 1);
        commonware_macros::select! {
            result = &mut future => {
                panic!("future epoch received a result before handoff: {result:?}")
            },
            _ = context.sleep(Duration::from_millis(250)) => {},
        }
        assert_eq!(
            accepted(
                alice
                    .pay(&context, &mut alice_chain, service.address, &[(1, 2)])
                    .await
                    .unwrap(),
            )
            .epoch,
            0
        );

        // The next driver tick hands off, and the retried send is receipted in epoch 1.
        gate.lock().readback = false;
        drive_closes(&context, &mut alice_chain, &operator, TIMING)
            .await
            .unwrap();
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let (receipt, held) = future.await.unwrap();
        assert_eq!((receipt.epoch, held), (1, 1));
        {
            let sent = service.sends.lock();
            let retries = sent
                .iter()
                .filter(|send| send.authorization.body().payer() == &payer)
                .collect::<Vec<_>>();
            assert!(retries.len() >= 2);
            assert!(retries.iter().all(|send| **send == pending));
        }
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        release.release();
        operator.lock().wait_for_closes().unwrap();
        service.stop().await;
    });
}

/// Admits the operator's retained certified close for `epoch` on the harness
/// chain.
async fn admit(
    control: &harness::Control,
    operator: &Mutex<Operator>,
    epoch: u64,
) -> SettlementResult {
    let result = operator
        .lock()
        .retained_result(epoch)
        .unwrap()
        .expect("the close is retained");
    control
        .submit(SettlementTx::Admit(AdmitRequest::from(&result)))
        .await;
    assert!(matches!(
        control.record(admitted_key(&deployment(), epoch)).await,
        Some(Record::Admitted(_))
    ));
    result
}

/// The production payment coordinator and RPC dispatch serving one operator
/// over the harness chain.
struct Service {
    address: SocketAddr,
    /// Every submitted send, in arrival order.
    sends: Arc<Mutex<Vec<operator_rpc::AcceptSendRequest>>>,
    /// Withdrawal arrival proves each blocked RPC reached service dispatch.
    withdrawals: Arc<Mutex<Vec<operator_rpc::ApplyWithdrawalRequest>>>,
    server: Handle<()>,
    payments: Handle<()>,
}

impl Service {
    async fn start(
        context: &deterministic::Context,
        control: &harness::Control,
        operator: &Arc<Mutex<Operator>>,
    ) -> Self {
        Self::start_held(context, control, operator, None, 0).await
    }

    async fn start_held(
        context: &deterministic::Context,
        control: &harness::Control,
        operator: &Arc<Mutex<Operator>>,
        gate: Option<Arc<Mutex<RegistrationGate>>>,
        port: u16,
    ) -> Self {
        let listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let strategy = operator.lock().payment_strategy();
        let (payment_sender, payments) = payments::start(
            context.child("payments"),
            HeldRegistration {
                inner: client(context, control),
                gate: gate.clone(),
            },
            operator.clone(),
            strategy,
            TIMING,
        );
        let sends = Arc::new(Mutex::new(Vec::new()));
        let withdrawals = Arc::new(Mutex::new(Vec::new()));
        let server = context.child("rpc").spawn({
            let operator = operator.clone();
            let control = control.clone();
            let sends = sends.clone();
            let withdrawals = withdrawals.clone();
            move |server_context| async move {
                let request_context = server_context.child("request");
                payments::serve_connections(server_context, listener, move |request| {
                    let operator = operator.clone();
                    let mut chain = HeldRegistration {
                        inner: client(&request_context, &control),
                        gate: gate.clone(),
                    };
                    let payment_sender = payment_sender.clone();
                    let gate = gate.clone();
                    let sends = sends.clone();
                    let withdrawals = withdrawals.clone();
                    let context = request_context.child("connection");
                    async move {
                        match operator_rpc::decode_request(request) {
                            Ok(operator_rpc::OperatorRequest::AcceptSend(request)) => {
                                sends.lock().push(request.clone());
                                payments::submit(
                                    &payment_sender,
                                    operator_rpc::AcceptSendsRequest {
                                        sends: vec![request],
                                    },
                                    payments::ResponseKind::Single,
                                )
                                .await
                            }
                            Ok(request) => {
                                if let operator_rpc::OperatorRequest::ApplyWithdrawal(request) =
                                    &request
                                {
                                    withdrawals.lock().push(request.clone());
                                }
                                if matches!(request, operator_rpc::OperatorRequest::PaymentHead(_))
                                    && gate.as_ref().is_some_and(|gate| gate.lock().hide_heads)
                                {
                                    return rpc::error_response("payment head withheld".into());
                                }
                                match prepare_request(
                                    &context, &mut chain, &operator, &request, TIMING,
                                )
                                .await
                                {
                                    Ok(Some(response)) => response,
                                    Ok(None) => {
                                        operator_rpc::handle_decoded(&mut operator.lock(), request)
                                    }
                                    Err(error) => rpc::error_response(format!("{error:#}")),
                                }
                            }
                            Err(error) => rpc::error_response(format!("{error:#}")),
                        }
                    }
                })
                .await;
            }
        });
        Self {
            address,
            sends,
            withdrawals,
            server,
            payments,
        }
    }

    async fn stop(self) {
        self.server.abort();
        self.payments.abort();
        let _ = self.server.await;
        let _ = self.payments.await;
    }
}

/// A cold wallet's first successor receipt waits for neither certification
/// nor admission of the predecessor: it is accepted under the certified
/// successor anchor while the predecessor's close is held after preparation,
/// and again while its certified result is retained but not admitted.
#[test]
fn successor_receipts_while_the_predecessor_is_held_at_certify_and_admit() {
    for stage in [Stage::Certify, Stage::Admit] {
        deterministic::Runner::timed(Duration::from_secs(20)).start(move |context| async move {
            let control = chain(&context).await;
            let operator = operator();
            let service = Service::start(&context, &control, &operator).await;
            let mut alice = Agent::new(0).unwrap();
            let mut bob = Agent::new(1).unwrap();
            let mut alice_chain = client(&context, &control);
            let mut bob_chain = client(&context, &control);

            // Alice's first receipt registers epoch 0.
            let first = accepted(
                alice
                    .pay(&context, &mut alice_chain, service.address, &[(1, 2)])
                    .await
                    .unwrap(),
            );
            assert_eq!(first.epoch, 0);

            // The cut worker holds at the stage. Only the admission hold follows
            // certification, so only it has retained the certified result.
            let (started, release) = operator.lock().pause_close_at(stage);
            let mut release = ReleaseClose(Some(release));
            assert_eq!(
                operator_rpc::start_close(&context, service.address, 0)
                    .await
                    .unwrap()
                    .epoch,
                0
            );
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(
                operator.lock().retained_result(0).unwrap().is_some(),
                stage == Stage::Admit
            );

            // Bob's first payment binds epoch 1's certified registration while epoch 0
            // remains unadmitted.
            let second = accepted(
                bob.pay(&context, &mut bob_chain, service.address, &[(0, 1)])
                    .await
                    .unwrap(),
            );
            assert_eq!(second.epoch, 1);
            assert_eq!(bob.receipt_count(), 1);
            let registration = bob_chain
                .registration_at(&context, 1)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(second.acceptance.ack.body().anchor(), &registration.anchor);
            assert_eq!(registration.deadlines, None);
            assert!(bob_chain.admitted(&context, 0).await.unwrap().is_none());

            // The released worker finishes the close.
            release.release();
            operator.lock().wait_for_closes().unwrap();
            assert!(operator.lock().retained_result(0).unwrap().is_some());
            service.stop().await;
        });
    }
}

/// A send that reaches the operator after its epoch is cut is receipted in the successor for
/// the same entries while the predecessor's close is still held unbuilt.
///
/// Alice signs her second payment under her cached epoch-0 context after the cut. The
/// operator reports her frozen epoch-0 endpoint, which her first receipt confirms, so she
/// signs the same entries again under epoch 1, bound to that endpoint's root. Her epoch-1
/// receipt arrives before epoch 0's close is even prepared.
#[test]
fn stale_send_into_held_predecessor_is_receipted_in_successor() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        let control = chain(&context).await;
        let operator = operator();
        let service = Service::start(&context, &control, &operator).await;
        let mut alice = Agent::new(0).unwrap();
        let mut alice_chain = client(&context, &control);

        // Alice's first payment registers epoch 0 and caches its context.
        let first = accepted(
            alice
                .pay(&context, &mut alice_chain, service.address, &[(1, 2)])
                .await
                .unwrap(),
        );
        assert_eq!(first.epoch, 0);

        // The operator cuts epoch 0 and holds its close before preparation.
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        assert_eq!(
            operator_rpc::start_close(&context, service.address, 0)
                .await
                .unwrap()
                .epoch,
            0
        );
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        // The epoch-0 send earns a report, and the same entries are receipted in epoch 1.
        let before = service.sends.lock().len();
        let second = accepted(
            alice
                .pay(&context, &mut alice_chain, service.address, &[(1, 3)])
                .await
                .unwrap(),
        );
        let sent = service.sends.lock()[before..].to_vec();
        assert_eq!(sent.len(), 2);
        let stale = sent[0].authorization.body();
        assert_eq!(
            (stale.epoch(), stale.seq(), stale.cumulative_debit()),
            (0, 2, 5)
        );
        assert_eq!(sent[1].entries, sent[0].entries);
        let reported = OutVector::new(
            0,
            alice.account(),
            vec![OutEntry {
                recipient: crate::protocol::wallets()[1].public_key(),
                cumulative: 2,
                count: 1,
            }],
        )
        .unwrap()
        .root::<Sha256, Digest>()
        .unwrap();
        assert_eq!(second.epoch, 1);
        let body = second.acceptance.ack.body();
        assert_eq!((body.seq(), body.cumulative_debit()), (1, 3));
        assert_eq!(second.acceptance.ack.predecessor(), reported);
        assert_eq!(sent[1].authorization.body(), body);
        let registration = alice_chain
            .registration_at(&context, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body.anchor(), &registration.anchor);

        // Epoch 0 is still held before preparation, and Alice was debited once per payment.
        assert!(alice_chain.admitted(&context, 0).await.unwrap().is_none());
        assert!(operator.lock().retained_result(0).unwrap().is_none());
        assert_eq!(alice.receipt_count(), 2);
        assert_eq!(
            operator
                .lock()
                .payment_head(&alice.account())
                .unwrap()
                .balance,
            95
        );
        release.release();
        service.stop().await;
    });
}

/// A deposit that executes while an epoch is registered waits in the inbox and
/// leaves the registered boundary untouched.
///
/// The operator observes the deposit's inbox entry but leaves it untaken while
/// the registered epoch's boundary is published. The cut's successor takes it,
/// and its depositor spends it in the successor while the predecessor's close
/// is held. Admitting the predecessor leaves the deposit pending for the
/// successor.
#[test]
fn deposit_during_registered_epoch_joins_the_successor() {
    deterministic::Runner::timed(Duration::from_secs(90)).start(|context| async move {
        let control = chain(&context).await;
        let operator = operator();
        let service = Service::start(&context, &control, &operator).await;
        let mut alice = Agent::new(0).unwrap();
        let mut carol = Agent::new(2).unwrap();
        let mut alice_chain = client(&context, &control);
        let mut carol_chain = client(&context, &control);

        // Alice's payment registers epoch 0 with an empty deposit boundary.
        accepted(
            alice
                .pay(&context, &mut alice_chain, service.address, &[(1, 2)])
                .await
                .unwrap(),
        );
        let registered = carol_chain
            .registration_at(&context, 0)
            .await
            .unwrap()
            .unwrap();

        // Carol's deposit executes after epoch 0 registered over an empty
        // inbox, so it takes index 0 and epoch 0's record is unchanged.
        let deposit = carol.deposit(&context, &mut carol_chain, 10).await.unwrap();
        let effect = carol_chain
            .deposit(&context, deposit.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(effect.index, 0);
        assert_eq!(registered.pulled, 0..0);
        assert_eq!(
            carol_chain.registration_at(&context, 0).await.unwrap(),
            Some(registered)
        );

        // The operator observes the entry without crediting published epoch 0.
        let staged = observe(&context, &mut carol_chain, &operator)
            .await
            .unwrap();
        assert!(staged.is_empty());
        assert_eq!(operator.lock().observed().unwrap(), 1);
        assert_eq!(
            operator
                .lock()
                .payment_head(&carol.account())
                .unwrap()
                .balance,
            100
        );

        // The cut credits the deposit to epoch 1 while epoch 0's close is held.
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        assert_eq!(
            operator_rpc::start_close(&context, service.address, 0)
                .await
                .unwrap()
                .epoch,
            0
        );
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            operator
                .lock()
                .payment_head(&carol.account())
                .unwrap()
                .balance,
            110
        );

        // Carol spends beyond her genesis balance in epoch 1, whose certified
        // registration pulls her deposit.
        let spent = accepted(
            carol
                .pay(&context, &mut carol_chain, service.address, &[(0, 105)])
                .await
                .unwrap(),
        );
        assert_eq!(spent.epoch, 1);
        let successor = carol_chain
            .registration_at(&context, 1)
            .await
            .unwrap()
            .unwrap();
        let pulled = DepositBatch::new(vec![DepositRecord::new(carol.account(), 10).unwrap()])
            .unwrap()
            .root::<Sha256>()
            .unwrap();
        assert_eq!(successor.deposits_root, pulled);
        assert_eq!(successor.pulled, 0..1);
        assert_eq!(spent.acceptance.ack.body().anchor(), &successor.anchor);
        assert!(carol_chain.admitted(&context, 0).await.unwrap().is_none());

        // Admitting epoch 0 consumes none of its empty pull: custody keeps the
        // deposit, and epoch 1 becomes the frontier.
        release.release();
        operator.lock().wait_for_closes().unwrap();
        admit(&control, &operator, 0).await;
        let status = carol_chain.recent_status(&context).await.unwrap();
        assert_eq!(status.custody, 410);
        assert_eq!((status.next_admission, status.next_registration), (1, 2));
        let promoted = carol_chain
            .registration_at(&context, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(promoted.deposits_root, pulled);
        assert!(promoted.deadlines.is_some());
        service.stop().await;
    });
}

/// Three epochs overlap one unfinished close: epoch 0 is held, epoch 1 is cut
/// and queued behind it, and epoch 2 accepts a verified payment. Admitting
/// epoch 0 promotes epoch 1 alone.
#[test]
fn three_epochs_queue_behind_a_held_predecessor() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let control = chain(&context).await;
        let operator = operator();
        let service = Service::start(&context, &control, &operator).await;
        let mut alice = Agent::new(0).unwrap();
        let mut bob = Agent::new(1).unwrap();
        let mut carol = Agent::new(2).unwrap();
        let mut alice_chain = client(&context, &control);
        let mut bob_chain = client(&context, &control);
        let mut carol_chain = client(&context, &control);

        // Alice's payment registers epoch 0, whose close is cut and held.
        accepted(
            alice
                .pay(&context, &mut alice_chain, service.address, &[(1, 2)])
                .await
                .unwrap(),
        );
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        assert!(
            !operator_rpc::start_close(&context, service.address, 0)
                .await
                .unwrap()
                .queued
        );
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        // Bob pays in epoch 1, which is cut behind the held close.
        let second = accepted(
            bob.pay(&context, &mut bob_chain, service.address, &[(2, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(second.epoch, 1);
        assert!(
            operator_rpc::start_close(&context, service.address, 1)
                .await
                .unwrap()
                .queued
        );

        // Carol's payment is accepted in epoch 2.
        let third = accepted(
            carol
                .pay(&context, &mut carol_chain, service.address, &[(0, 4)])
                .await
                .unwrap(),
        );
        assert_eq!(third.epoch, 2);

        // Three epochs are registered, and only the frontier has deadlines.
        let status = carol_chain.recent_status(&context).await.unwrap();
        assert_eq!((status.next_admission, status.next_registration), (0, 3));
        for (epoch, receipt) in [(1, &second), (2, &third)] {
            let record = carol_chain
                .registration_at(&context, epoch)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.deadlines, None);
            assert_eq!(receipt.acceptance.ack.body().anchor(), &record.anchor);
        }
        let frontier = carol_chain
            .registration_at(&context, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(frontier.deadlines.is_some());
        assert!(carol_chain.admitted(&context, 0).await.unwrap().is_none());

        // Admitting epoch 0 promotes epoch 1, and epoch 2 stays queued.
        release.release();
        operator.lock().wait_for_closes().unwrap();
        admit(&control, &operator, 0).await;
        let status = carol_chain.recent_status(&context).await.unwrap();
        assert_eq!((status.next_admission, status.next_registration), (1, 3));
        let promoted = carol_chain
            .registration_at(&context, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(promoted.deadlines.is_some());
        let queued = carol_chain
            .registration_at(&context, 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queued.deadlines, None);
        service.stop().await;
    });
}

/// Signs intake against a verified current root with the full allowed notice.
async fn withdrawal(
    context: &deterministic::Context,
    chain: &mut Client,
    wallet: usize,
    amount: u64,
) -> SignedWithdrawal<crate::protocol::Key, Digest> {
    let head = chain.recent_status(context).await.unwrap();
    let wallet = &crate::protocol::wallets()[wallet];
    SignedWithdrawal::sign(
        deployment(),
        wallet.public_key().encode(),
        WithdrawalAction::Amount(NonZeroU64::new(amount).unwrap()),
        head.height
            + crate::protocol::settlement_config(&TIMING)
                .unwrap()
                .maximum_withdrawal_notice
                .get(),
        wallet.signer(),
    )
}

/// Requires a dispatched withdrawal to remain blocked across a held lifecycle gate.
async fn pending<T: std::fmt::Debug + Send + 'static>(
    context: &deterministic::Context,
    request: &mut Handle<T>,
) {
    commonware_macros::select! {
        result = request => panic!("withdrawal returned before certified handoff: {result:?}"),
        _ = context.sleep(Duration::from_millis(250)) => {},
    }
}

/// Runs the public withdrawal RPC concurrently with successor publication.
fn apply(
    context: &deterministic::Context,
    address: SocketAddr,
    request: &SignedWithdrawal<crate::protocol::Key, Digest>,
) -> Handle<Result<operator_rpc::WithdrawalAck>> {
    let request = request.clone();
    context
        .child("apply_withdrawal")
        .spawn(move |context| async move {
            operator_rpc::apply_withdrawal(
                &context,
                address,
                operator_rpc::ApplyWithdrawalRequest { request },
            )
            .await
        })
}

/// A withdrawal staged into the successor, and its exact retry, are acknowledged only after the
/// certified handoff. Until then the predecessor keeps receipting and its balances stay spendable.
#[test]
fn future_withdrawal_ack_and_exact_retry_wait_for_certified_handoff() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        // Alice pays in the registered epoch 0.
        let control = chain(&context).await;
        let operator = operator();
        let (publishing, published) = oneshot::channel();
        let (reading, read) = oneshot::channel();
        let gate = Arc::new(Mutex::new(RegistrationGate {
            publish: true,
            readback: true,
            publishing: Some(publishing),
            reading: Some(reading),
            ..RegistrationGate::default()
        }));
        let service =
            Service::start_held(&context, &control, &operator, Some(gate.clone()), 0).await;
        let mut alice = Agent::new(0).unwrap();
        let mut chain = client(&context, &control);
        assert_eq!(
            accepted(
                alice
                    .pay(&context, &mut chain, service.address, &[(1, 2)])
                    .await
                    .unwrap()
            )
            .epoch,
            0,
        );

        // Private successor intake leaves the registered predecessor and its balances writable.
        let request = withdrawal(&context, &mut chain, 1, 3).await;
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        let mut original = apply(&context, service.address, &request);
        let staged = loop {
            if let Some(staged) = operator.lock().staged_withdrawal(&request).unwrap() {
                break staged;
            }
            commonware_runtime::reschedule().await;
        };
        assert_eq!(staged.epoch, 1);
        assert_eq!(operator.lock().status().unwrap().epoch, 0);
        let mut replay = apply(&context, service.address, &request);
        while service.withdrawals.lock().len() < 2 {
            commonware_runtime::reschedule().await;
        }

        // Submission and certified read-back each hold ACKs before the payment handoff.
        let driver = start_close_driver(
            &context,
            HeldRegistration {
                inner: client(&context, &control),
                gate: Some(gate.clone()),
            },
            operator.clone(),
            TIMING,
        );
        published.await.unwrap();
        assert!(
            control
                .record(registration_key(&deployment(), 1))
                .await
                .is_none()
        );
        pending(&context, &mut original).await;
        pending(&context, &mut replay).await;
        assert_eq!(
            accepted(
                alice
                    .pay(&context, &mut chain, service.address, &[(1, 3)])
                    .await
                    .unwrap()
            )
            .epoch,
            0,
        );
        assert_eq!(operator.lock().status().unwrap().epoch, 0);
        assert_eq!(
            operator
                .lock()
                .snapshot()
                .unwrap()
                .accounts
                .iter()
                .find(|account| account.name == crate::protocol::wallets()[1].name)
                .unwrap()
                .balance,
            105,
            "private future intake must leave the current balance spendable",
        );
        gate.lock().publish = false;
        read.await.unwrap();
        let registered = chain.registration_at(&context, 1).await.unwrap().unwrap();
        assert_eq!(
            registered.withdrawals_root,
            WithdrawalBatch::new(vec![request.clone()])
                .unwrap()
                .root::<Sha256>()
                .unwrap(),
        );
        assert_eq!(operator.lock().status().unwrap().epoch, 0);
        pending(&context, &mut original).await;
        pending(&context, &mut replay).await;

        // Handoff resolves the deferred withdrawal against the complete predecessor tail.
        gate.lock().readback = false;
        let original = original.await.unwrap().unwrap();
        let replay = replay.await.unwrap().unwrap();
        assert_eq!(original, replay);
        assert_eq!(original.epoch, staged.epoch);
        assert_eq!(original.digest, operator_rpc::withdrawal_digest(&request));
        assert_eq!(operator.lock().status().unwrap().epoch, 1);
        driver.abort();
        let _ = driver.await;
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            operator
                .lock()
                .snapshot()
                .unwrap()
                .accounts
                .iter()
                .find(|account| account.name == crate::protocol::wallets()[1].name)
                .unwrap()
                .balance,
            102,
        );

        let before = service.sends.lock().len();
        let successor = accepted(
            alice
                .pay(&context, &mut chain, service.address, &[(1, 1)])
                .await
                .unwrap(),
        );
        assert_eq!(successor.epoch, 1);
        assert_eq!(successor.acceptance.ack.body().anchor(), &registered.anchor);
        let payer = crate::protocol::wallets()[0].public_key();
        let sent = service.sends.lock()[before..]
            .iter()
            .filter(|send| send.authorization.body().payer() == &payer)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(sent.len(), 2);
        let predecessor = OutVector::new(
            0,
            payer,
            vec![OutEntry {
                recipient: crate::protocol::wallets()[1].public_key(),
                cumulative: 5,
                count: 2,
            }],
        )
        .unwrap()
        .root::<Sha256, Digest>()
        .unwrap();
        assert_eq!(sent[1].authorization.predecessor(), predecessor);
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        release.release();
        operator.lock().wait_for_closes().unwrap();
        service.stop().await;
    });
}

/// Owns the SQLite store across a cancelled request and operator restart.
struct WithdrawalDatabase(PathBuf);

impl WithdrawalDatabase {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "commonware-terminal-withdrawal-overlap-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn path(&self) -> PathBuf {
        self.0.join("operator.sqlite")
    }
}

impl Drop for WithdrawalDatabase {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// A successor withdrawal whose request is cancelled after publication survives an operator
/// restart. Its replay waits for the handoff, the handoff completes without any request
/// attached, and a later replay answers from the retained row without reading the chain.
#[test]
fn cancelled_future_withdrawal_replays_after_restart_and_independent_handoff() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        // Epoch 0 registers and pays, and a signed withdrawal waits for intake.
        let database = WithdrawalDatabase::new();
        let control = chain(&context).await;
        let operator = Arc::new(Mutex::new(
            Operator::open(&database.path(), NonZeroUsize::MIN).unwrap(),
        ));
        let mut chain = client(&context, &control);
        register_epoch(&context, &mut chain, &operator, TIMING, |_| Ok(true))
            .await
            .unwrap();
        operator.lock().pay(0, 1, 2).unwrap();
        let request = withdrawal(&context, &mut chain, 1, 3).await;
        let (publishing, published) = oneshot::channel();
        let gate = Arc::new(Mutex::new(RegistrationGate {
            publish: true,
            readback: true,
            publishing: Some(publishing),
            ..RegistrationGate::default()
        }));

        // The service attempt owns polling. SQLite owns intake and publication intent.
        let mut original = context.child("cancelled_withdrawal").spawn({
            let operator = operator.clone();
            let request = request.clone();
            let mut chain = HeldRegistration {
                inner: client(&context, &control),
                gate: Some(gate.clone()),
            };
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest { request },
            );
            move |context| async move {
                prepare_request(&context, &mut chain, &operator, &request, TIMING).await
            }
        });
        let staged = loop {
            if let Some(staged) = operator.lock().staged_withdrawal(&request).unwrap() {
                break staged;
            }
            commonware_runtime::reschedule().await;
        };
        assert_eq!(staged.epoch, 1);
        pending(&context, &mut original).await;
        published.await.unwrap();
        original.abort();
        assert!(original.await.is_err());
        assert!(operator.lock().successor_pending().unwrap());
        assert_eq!(operator.lock().status().unwrap().epoch, 0);
        assert!(
            control
                .record(registration_key(&deployment(), 1))
                .await
                .is_none()
        );
        drop(operator);

        // The restarted operator holds the replay until the registration read-back is released.
        let operator = Arc::new(Mutex::new(
            Operator::open(&database.path(), NonZeroUsize::MIN).unwrap(),
        ));
        let service =
            Service::start_held(&context, &control, &operator, Some(gate.clone()), 0).await;
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        let driver = start_close_driver(
            &context,
            HeldRegistration {
                inner: client(&context, &control),
                gate: Some(gate.clone()),
            },
            operator.clone(),
            TIMING,
        );
        let mut replay = apply(&context, service.address, &request);
        while service.withdrawals.lock().is_empty() {
            commonware_runtime::reschedule().await;
        }
        pending(&context, &mut replay).await;
        assert_eq!(operator.lock().status().unwrap().epoch, 0);
        let (reading, read) = oneshot::channel();
        gate.lock().reading = Some(reading);
        gate.lock().publish = false;
        read.await.unwrap();
        let registered = chain.registration_at(&context, 1).await.unwrap().unwrap();
        assert_eq!(
            registered.withdrawals_root,
            WithdrawalBatch::new(vec![request.clone()])
                .unwrap()
                .root::<Sha256>()
                .unwrap(),
        );
        pending(&context, &mut replay).await;

        // Server shutdown aborts its supervised connection tasks before the driver can hand off.
        replay.abort();
        assert!(replay.await.is_err());
        service.stop().await;
        gate.lock().readback = false;
        while operator.lock().status().unwrap().epoch == 0 {
            commonware_runtime::reschedule().await;
        }
        assert_eq!(operator.lock().status().unwrap().epoch, 1);
        driver.abort();
        let _ = driver.await;
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        register_successor(&context, &mut chain, &operator, 1, TIMING)
            .await
            .unwrap();
        assert_eq!(operator.lock().status().unwrap().epoch, 2);

        // Historical replays use their exact retained row while registration read-back is held.
        // Bindings belong to the deterministic runtime, so each listener has a distinct address.
        gate.lock().readback = true;
        let service =
            Service::start_held(&context, &control, &operator, Some(gate.clone()), 1).await;
        let mut historical = apply(&context, service.address, &request);
        let historical = commonware_macros::select! {
            result = &mut historical => result.unwrap().unwrap(),
            _ = context.sleep(Duration::from_millis(250)) => {
                panic!("retained exact replay waited for the chain")
            },
        };
        assert_eq!(historical.epoch, staged.epoch);
        assert_eq!(historical.digest, operator_rpc::withdrawal_digest(&request));
        release.release();
        operator.lock().wait_for_closes().unwrap();
        service.stop().await;
        drop(operator);
    });
}

/// A private successor withdrawal replaced by a chain-queued request for its account never
/// receives an ACK, even once its original epoch becomes live. The queued replacement is
/// registered and answers from its retained row.
#[test]
fn replaced_future_withdrawal_cannot_ack_when_its_original_epoch_becomes_live() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        // Epoch 0 registers and pays, and a fresh withdrawal stages into epoch 1.
        let control = chain(&context).await;
        let operator = operator();
        let mut chain = client(&context, &control);
        register_epoch(&context, &mut chain, &operator, TIMING, |_| Ok(true))
            .await
            .unwrap();
        operator.lock().pay(0, 1, 2).unwrap();
        let request = withdrawal(&context, &mut chain, 1, 3).await;
        let staged = stage_withdrawal(
            &context,
            &mut chain,
            &operator,
            &operator_rpc::ApplyWithdrawalRequest {
                request: request.clone(),
            },
            TIMING,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(staged.epoch, 1);

        // The inbox selects the queued successor request while the original private row remains.
        let replacement = withdrawal(&context, &mut chain, 1, 4).await;
        let opening = operator
            .lock()
            .withdrawal_opening(replacement.account())
            .unwrap();
        control
            .submit(SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: replacement.clone(),
                opening: opening.opening,
            }))
            .await;
        assert_eq!(
            chain
                .withdrawal(&context, replacement.account().clone())
                .await
                .unwrap(),
            Some(replacement.clone())
        );
        observe(&context, &mut chain, &operator).await.unwrap();
        assert_eq!(
            operator
                .lock()
                .staged_withdrawal(&request)
                .unwrap()
                .unwrap()
                .epoch,
            staged.epoch
        );

        // The original request's retry waits while the successor registration is held.
        let (publishing, published) = oneshot::channel();
        let (reading, read) = oneshot::channel();
        let gate = Arc::new(Mutex::new(RegistrationGate {
            publish: true,
            readback: true,
            publishing: Some(publishing),
            reading: Some(reading),
            ..RegistrationGate::default()
        }));
        let service =
            Service::start_held(&context, &control, &operator, Some(gate.clone()), 0).await;
        let (started, release) = operator.lock().pause_next_close();
        let mut release = ReleaseClose(Some(release));
        let mut original = apply(&context, service.address, &request);
        while service.withdrawals.lock().is_empty() {
            commonware_runtime::reschedule().await;
        }
        let driver = start_close_driver(
            &context,
            HeldRegistration {
                inner: client(&context, &control),
                gate: Some(gate.clone()),
            },
            operator.clone(),
            TIMING,
        );
        published.await.unwrap();
        pending(&context, &mut original).await;
        assert_eq!(operator.lock().status().unwrap().epoch, 0);
        gate.lock().publish = false;
        read.await.unwrap();
        let registered = chain.registration_at(&context, 1).await.unwrap().unwrap();
        assert_eq!(
            registered.withdrawals_root,
            WithdrawalBatch::new(vec![replacement.clone()])
                .unwrap()
                .root::<Sha256>()
                .unwrap(),
        );
        assert_ne!(
            registered.withdrawals_root,
            WithdrawalBatch::new(vec![request.clone()])
                .unwrap()
                .root::<Sha256>()
                .unwrap(),
        );
        pending(&context, &mut original).await;

        // An ACK requires the exact retained request as well as an operational target epoch.
        gate.lock().readback = false;
        assert!(
            original.await.unwrap().is_err(),
            "the replaced authorization received an ACK"
        );
        assert_eq!(operator.lock().status().unwrap().epoch, staged.epoch);
        driver.abort();
        let _ = driver.await;
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(operator.lock().staged_withdrawal(&request).is_err());
        let retained = apply(&context, service.address, &replacement)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.epoch, staged.epoch);
        assert_eq!(
            retained.digest,
            operator_rpc::withdrawal_digest(&replacement)
        );
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        release.release();
        operator.lock().wait_for_closes().unwrap();
        service.stop().await;
    });
}

/// The operator's live epoch 1 after its native balance can no longer pay the epoch fee.
struct Unfunded {
    control: harness::Control,
    operator: Arc<Mutex<Operator>>,
    service: Service,
    driver: Handle<()>,
    alice: Agent,
    bob: Agent,
    chain: Client,
    /// The fee recipient's native balance after the operator's balance is drained.
    fees: u64,
    /// The native fee one epoch registration pays.
    fee: u64,
}

/// Finalizes epoch 0 with Alice's payment of 7 to Bob, drains the operator's native balance,
/// and receipts Alice's payment of 5 to Bob in epoch 1. The close driver then tries to register
/// epoch 2, and every attempt fails without charging a fee.
async fn unfunded(context: &deterministic::Context) -> Unfunded {
    let control = chain(context).await;
    let operator = operator();
    let service = Service::start(context, &control, &operator).await;
    let mut alice = Agent::new(0).unwrap();
    let bob = Agent::new(1).unwrap();
    let mut chain = client(context, &control);
    let native = control.identity().native.clone();
    let entry = native
        .deployments
        .iter()
        .find(|entry| entry.deployment.digest() == &deployment())
        .unwrap();
    let fee = native.epoch_cost(entry.max_dealing_bytes).unwrap();
    let owner = crate::protocol::operator_key();

    // Epoch 0 finalizes with Alice's payment to Bob.
    let first = accepted(
        alice
            .pay(context, &mut chain, service.address, &[(1, 7)])
            .await
            .unwrap(),
    );
    assert_eq!(first.epoch, 0);
    operator_rpc::start_close(context, service.address, 0)
        .await
        .unwrap();
    operator.lock().wait_for_closes().unwrap();
    let close = operator.lock().retained_result(0).unwrap().unwrap();
    let height = control.advance(0).await;
    control
        .advance(close.context.admission_deadline() - height - 1)
        .await;
    admit(&control, &operator, 0).await;
    let height = control.advance(0).await;
    control
        .advance(close.context.challenge_deadline() - height + 1)
        .await;
    assert_eq!(chain.status(context).await.unwrap().last_finalized, Some(0));

    // The operator's native balance is drained.
    let balance = chain
        .native_balance(context, native.chain_id(), owner.clone())
        .await
        .unwrap();
    chain
        .deliver(
            context,
            &SettlementTx::NativeTransfer(crate::chain::tx::NativeTransferRequest::sign(
                native.chain_id(),
                Sha256::hash(&[b"drain-operator"]),
                crate::protocol::Wallet::from_seed("fee sink", 9_999).public_key(),
                balance,
                &crate::protocol::operator_signer(0),
            )),
        )
        .await
        .unwrap();
    assert_eq!(
        chain
            .native_balance(context, native.chain_id(), owner.clone())
            .await
            .unwrap(),
        0
    );
    let fees = chain
        .native_balance(context, native.chain_id(), native.fee_recipient.clone())
        .await
        .unwrap();

    // Alice pays Bob in epoch 1, and every successor registration fails without a fee.
    let second = accepted(
        alice
            .pay(context, &mut chain, service.address, &[(1, 5)])
            .await
            .unwrap(),
    );
    assert_eq!(second.epoch, 1);
    let driver = start_close_driver(context, client(context, &control), operator.clone(), TIMING);
    while !operator.lock().successor_pending().unwrap() {
        commonware_runtime::reschedule().await;
    }
    control.advance(10).await;
    assert!(
        control
            .record(registration_key(&deployment(), 2))
            .await
            .is_none()
    );
    assert_eq!(operator.lock().status().unwrap().epoch, 1);
    assert_eq!(
        chain
            .native_balance(context, native.chain_id(), owner)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        chain
            .native_balance(context, native.chain_id(), native.fee_recipient.clone())
            .await
            .unwrap(),
        fees
    );
    Unfunded {
        control,
        operator,
        service,
        driver,
        alice,
        bob,
        chain,
        fees,
        fee,
    }
}

/// An operator that cannot pay its successor's epoch fee faults the deployment, and every
/// account's finalized balance leaves through the chain.
///
/// The operator's successor registrations fail, so live epoch 1 never closes. The operator has
/// already published the successor boundary, so it stages no withdrawal, and Alice escalates
/// hers. Epoch 1 expires at its admission deadline. Hard-fault recovery pays each account its
/// balance at epoch 0's root, with Alice's queued Amount routed to her. The payment Alice made in
/// epoch 1 never settles.
#[test]
fn fee_exhaustion_faults_and_recovers_frozen_balances() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let Unfunded {
            control,
            operator,
            service,
            driver,
            mut alice,
            mut bob,
            mut chain,
            ..
        } = Box::pin(unfunded(&context)).await;
        let frozen = chain.status(&context).await.unwrap().state_root;

        // The operator stages no withdrawal, so Alice escalates hers.
        let crate::agent::WithdrawalOutcome::Signed { request, .. } = alice
            .withdraw(
                &context,
                &mut chain,
                service.address,
                WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()),
            )
            .await
            .unwrap()
        else {
            panic!("the unfunded operator acknowledged the withdrawal");
        };
        assert!(
            operator
                .lock()
                .staged_withdrawal(&request)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            alice
                .escalate_withdrawal(&context, &mut chain)
                .await
                .unwrap(),
            request
        );
        assert_eq!(
            chain.withdrawal(&context, alice.account()).await.unwrap(),
            Some(request)
        );

        // Epoch 1 expires at its admission deadline.
        let (admission, _) = chain
            .registration_at(&context, 1)
            .await
            .unwrap()
            .unwrap()
            .deadlines
            .unwrap();
        let height = control.advance(0).await;
        control.advance(admission - height).await;
        assert!(!chain.status(&context).await.unwrap().hard_faulted);
        control.advance(1).await;
        assert!(matches!(
            chain.fault(&context).await.unwrap(),
            Some(FaultRecord::Faulted(HardFaultReasonResponse::ExpiredRegistration {
                epoch: 1,
                expired_at,
                ..
            })) if expired_at == admission
        ));
        driver.abort();
        let _ = driver.await;
        service.stop().await;
        drop(operator);

        // Recovery pays each account its balance at epoch 0's root.
        let custody = chain.status(&context).await.unwrap().custody;
        let paid = native(&context, &mut chain, alice.account()).await;
        let received = native(&context, &mut chain, bob.account()).await;
        let release = alice
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            chain
                .hard_fault(&context, alice.account())
                .await
                .unwrap()
                .unwrap()
                .root,
            frozen
        );
        assert_eq!(
            release.released_custody,
            crate::protocol::INITIAL_BALANCE - 7
        );
        assert_eq!(
            release.withdrawal.as_ref().map(|output| output.amount()),
            Some(3)
        );
        assert_eq!(release.residual, crate::protocol::INITIAL_BALANCE - 10);
        let credited = bob
            .recover_hard_fault(&context, &mut chain)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            credited.released_custody,
            crate::protocol::INITIAL_BALANCE + 7
        );
        assert_eq!(
            native(&context, &mut chain, alice.account()).await,
            paid + crate::protocol::INITIAL_BALANCE - 7
        );
        assert_eq!(
            native(&context, &mut chain, bob.account()).await,
            received + crate::protocol::INITIAL_BALANCE + 7
        );
        assert_eq!(
            chain.status(&context).await.unwrap().custody,
            custody - 2 * crate::protocol::INITIAL_BALANCE
        );
    });
}

/// Funding the operator before the deadline resumes epochs.
///
/// The operator's successor registrations fail for want of the epoch fee. Alice transfers one
/// epoch fee to the operator's account, the close driver registers epoch 2 and cuts epoch 1,
/// and epoch 1's close finalizes Bob's credits from both epochs without a fault.
#[test]
fn operator_funding_before_deadline_resumes_epochs() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let Unfunded {
            control,
            operator,
            service,
            driver,
            mut alice,
            mut bob,
            mut chain,
            fees,
            fee,
        } = Box::pin(unfunded(&context)).await;
        let native_genesis = control.identity().native.clone();

        // Alice funds one epoch fee, and the close driver registers epoch 2 and cuts epoch 1.
        alice
            .transfer_native(&context, &mut chain, crate::protocol::operator_key(), fee)
            .await
            .unwrap();
        while control
            .record(registration_key(&deployment(), 2))
            .await
            .is_none()
            || operator.lock().status().unwrap().epoch != 2
        {
            commonware_runtime::reschedule().await;
        }
        assert_eq!(
            chain
                .native_balance(
                    &context,
                    native_genesis.chain_id(),
                    native_genesis.fee_recipient.clone(),
                )
                .await
                .unwrap(),
            fees + fee
        );

        // Epoch 1's close finalizes Bob's credits without a fault.
        operator.lock().wait_for_closes().unwrap();
        admit(&control, &operator, 1).await;
        let close = operator.lock().retained_result(1).unwrap().unwrap();
        let height = control.advance(0).await;
        control
            .advance(close.context.challenge_deadline() - height + 1)
            .await;
        let status = chain.status(&context).await.unwrap();
        assert_eq!(status.last_finalized, Some(1));
        assert!(!status.hard_faulted);
        assert_eq!(
            bob.balance(&context, &mut chain, UNREACHABLE)
                .await
                .unwrap(),
            crate::protocol::INITIAL_BALANCE + 12
        );
        driver.abort();
        let _ = driver.await;
        service.stop().await;
    });
}
