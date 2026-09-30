//! Payment admission across an unfinished predecessor close.

use super::*;
use crate::{
    agent::PaymentOutcome,
    chain::{
        harness,
        state::{Record, admitted_key, registration_key},
        tx::AdmitRequest,
    },
    operator::Stage,
    protocol::{SettlementResult, deployment},
};
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord},
    vector::{OutEntry, OutVector},
};
use commonware_runtime::deterministic;
use std::sync::mpsc::SyncSender;

const CHAIN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_703);
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
        assert_eq!(operator.lock().start_close(0).unwrap().epoch, 0);
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
    server: Handle<()>,
    payments: Handle<()>,
}

impl Service {
    async fn start(
        context: &deterministic::Context,
        control: &harness::Control,
        operator: &Arc<Mutex<Operator>>,
    ) -> Self {
        let listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let strategy = operator.lock().payment_strategy();
        let (payment_sender, payments) = payments::start(
            context.child("payments"),
            client(context, control),
            operator.clone(),
            strategy,
        );
        let sends = Arc::new(Mutex::new(Vec::new()));
        let server = context.child("rpc").spawn({
            let operator = operator.clone();
            let control = control.clone();
            let sends = sends.clone();
            move |server_context| async move {
                let request_context = server_context.child("request");
                payments::serve_connections(server_context, listener, move |request| {
                    let operator = operator.clone();
                    let mut chain = client(&request_context, &control);
                    let payment_sender = payment_sender.clone();
                    let sends = sends.clone();
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
            assert_eq!(operator.lock().start_close(0).unwrap().epoch, 0);
            started.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(
                operator.lock().retained_result(0).unwrap().is_some(),
                stage == Stage::Admit
            );

            // Bob's first payment registers epoch 1 behind the unadmitted epoch 0,
            // and its receipt binds that certified registration.
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
        assert_eq!(operator.lock().start_close(0).unwrap().epoch, 0);
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
        assert_eq!(operator.lock().start_close(0).unwrap().epoch, 0);
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
        assert!(!operator.lock().start_close(0).unwrap().queued);
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        // Bob's payment registers epoch 1, which is cut behind the held close.
        let second = accepted(
            bob.pay(&context, &mut bob_chain, service.address, &[(2, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(second.epoch, 1);
        assert!(operator.lock().start_close(1).unwrap().queued);

        // Carol's payment registers epoch 2 and is accepted.
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
