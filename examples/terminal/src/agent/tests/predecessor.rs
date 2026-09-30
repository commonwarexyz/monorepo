//! Wallet and recipient behavior around the implicit predecessor endpoint.

use super::*;
use crate::operator::SendsOutcome;
use commonware_clearing::bajillion::{challenge::ChallengeKind, transition::Terminal};
use std::sync::mpsc::SyncSender;

/// Starts the settlement chain with an admission window that outlasts every held close and
/// retry budget here, and a verified client over it.
async fn chain(context: &deterministic::Context) -> (harness::Control, Client) {
    chain_with(
        context,
        crate::protocol::Timing {
            admission_offset: 1_000,
            challenge_duration: 8,
        },
    )
    .await
}

/// Starts the settlement chain with `timing` and a verified client over it.
async fn chain_with(
    context: &deterministic::Context,
    timing: crate::protocol::Timing,
) -> (harness::Control, Client) {
    let control = harness::start_with_native(
        context,
        CHAIN,
        "chain",
        harness::native(crate::protocol::deployments()),
        timing,
    )
    .await;
    let client = Client::new(
        control.identity(),
        deployment(),
        vec![CHAIN],
        context.child("client_rng"),
    )
    .unwrap();
    (control, client)
}

/// Cuts the operator's live epoch and holds its close before preparation until the returned
/// sender releases it.
fn hold(operator: &mut Operator) -> SyncSender<()> {
    let epoch = operator.status().unwrap().epoch;
    let (started, release) = operator.pause_next_close();
    operator.start_close(epoch).unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    release
}

/// Releases a held close and waits until `epoch`'s close finishes, leaving later closes to
/// their own gates.
fn finish(operator: &mut Operator, release: SyncSender<()>, epoch: u64) -> SettlementResult {
    release.send(()).unwrap();
    while operator.poll_close(epoch).unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(5));
    }
    operator.retained_result(epoch).unwrap().unwrap()
}

/// Releases a held close, waits for every pending close, and admits `epoch`'s certified
/// close on the harness chain.
async fn release_and_admit(
    control: &harness::Control,
    operator: &mut Operator,
    release: SyncSender<()>,
    epoch: u64,
) -> SettlementResult {
    release.send(()).unwrap();
    operator.wait_for_closes().unwrap();
    let result = operator.retained_result(epoch).unwrap().unwrap();
    applied(control, &SettlementTx::Admit(AdmitRequest::from(&result))).await;
    result
}

/// The root of one payer's cumulative vector.
fn root(payer: Key, entries: Vec<OutEntry<Key>>) -> VectorRoot<Digest> {
    OutVector::new(0, payer, entries)
        .unwrap()
        .root::<Sha256, Digest>()
        .unwrap()
}

/// A report claiming the payer's endpoint in `epoch` is empty, bound to the empty root.
fn empty_report(context: &PaymentContext<Key, Digest>, epoch: u64) -> Bytes {
    operator_rpc::AcceptSendsResponse::Stale(operator_rpc::StaleResponse {
        context: context.clone(),
        epoch,
        cumulative_debit: 0,
        seq: 0,
        entries: Vec::new(),
        predecessor: empty(),
    })
    .encode()
}

/// Receives one request and drops the connection without a reply.
async fn drop_request<L: commonware_runtime::Listener>(
    listener: &mut L,
) -> operator_rpc::OperatorRequest {
    let (_, _sink, mut stream) = listener.accept().await.unwrap();
    operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap()).unwrap()
}

/// The staged sends of one submission, whichever method carried it.
fn sends(request: &operator_rpc::OperatorRequest) -> Vec<operator_rpc::AcceptSendRequest> {
    match request {
        operator_rpc::OperatorRequest::AcceptSend(request) => vec![request.clone()],
        operator_rpc::OperatorRequest::AcceptSends(request) => request.sends.clone(),
        _ => panic!("expected a payment submission"),
    }
}

/// The submission the wallet sends for `sends`.
fn submission(sends: Vec<operator_rpc::AcceptSendRequest>) -> operator_rpc::OperatorRequest {
    match <[_; 1]>::try_from(sends) {
        Ok([send]) => operator_rpc::OperatorRequest::AcceptSend(send),
        Err(sends) => {
            operator_rpc::OperatorRequest::AcceptSends(operator_rpc::AcceptSendsRequest { sends })
        }
    }
}

/// A send that reaches the operator after its epoch is cut is re-signed in the successor
/// against the reported endpoint while the cut epoch's close is still held.
///
/// The first payment is receipted in epoch 0. The operator cuts epoch 0 while the second is
/// in flight and reports the receipted endpoint, so the wallet re-signs the second payment in
/// epoch 1 bound to that endpoint's root after one head read.
#[test]
fn cut_resigns_against_reported_endpoint() {
    for entries in [vec![(1, 3)], vec![(1, 3), (2, 4)]] {
        deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
            let total = entries.iter().map(|(_, amount)| amount).sum::<u64>();
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let old = register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();

            // The first payment reads the head and is receipted in epoch 0.
            let staging = context.child("staging").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                relay(&mut listener, &mut operator).await;
                (listener, operator)
            });
            let mut agent = Agent::new(0).unwrap();
            let first = accepted(
                agent
                    .pay(&context, &mut chain, address, &[(1, 7)])
                    .await
                    .unwrap(),
            );
            assert_eq!(first.epoch, old.epoch());
            let (mut listener, mut operator) = staging.await.unwrap();

            // The operator cuts epoch 0, holds its close, and registers epoch 1.
            let release = hold(&mut operator);
            let live = register(&control, &mut operator).await;
            let reported = root(agent.account(), bob_edge(7, 1));

            // The in-flight epoch-0 send earns a report, and the wallet re-signs it under
            // epoch 1 after one head read.
            let rolling = context.child("rolling").spawn(move |_| async move {
                respond(&mut listener, |request| {
                    let [send] = sends(&request).try_into().unwrap();
                    let body = send.authorization.body();
                    assert_eq!(
                        (body.epoch(), body.seq(), body.cumulative_debit()),
                        (0, 2, 7 + total)
                    );
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentHead(_)
                    ));
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
                respond(&mut listener, |request| {
                    let [send] = sends(&request).try_into().unwrap();
                    let body = send.authorization.body();
                    assert_eq!(
                        (body.epoch(), body.seq(), body.cumulative_debit()),
                        (1, 1, total)
                    );
                    assert_eq!(send.authorization.predecessor(), reported);
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
                (operator, release)
            });
            let payment = accepted(
                agent
                    .pay(&context, &mut chain, address, &entries)
                    .await
                    .unwrap(),
            );
            let (_operator, _release) = rolling.await.unwrap();

            // The payment settled once, in epoch 1, while epoch 0's close is still held.
            assert_eq!(payment.epoch, live.epoch());
            assert_eq!(payment.total, total);
            assert_eq!(payment.acceptance.ack.predecessor(), reported);
            for (recipient, amount) in &entries {
                let entry = payment
                    .acceptance
                    .entries
                    .iter()
                    .find(|entry| entry.recipient == wallets()[*recipient].public_key())
                    .unwrap();
                assert_eq!((entry.cumulative, entry.count), (*amount, 1));
            }
            assert_eq!(agent.store.debits_since(0).unwrap(), 7 + total);
            assert_eq!(agent.receipt_count(), 1 + entries.len() as u64);
            assert!(agent.pending_payments.is_empty() && agent.superseded.is_empty());
            assert!(chain.admitted(&context, 0).await.unwrap().is_none());
        });
    }
}

/// A report whose endpoint lies below a receipt the wallet holds is unusable, so the wallet
/// retries the exact bytes until admission decides them.
///
/// The operator accepts a two-send batch, but its reply carries only the first receipt. After
/// the cut, a lying report claims an empty endpoint. Re-signing against it would pay the
/// receipted send twice once epoch 0 carries it, so the wallet waits, and admission then
/// concludes both sends in epoch 0.
#[test]
fn endpoint_below_held_receipt_waits_for_admission() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The operator accepts both sends, and the reply keeps only the first receipt.
        let partial = context.child("partial").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSends(request) = request else {
                    panic!("expected the staged batch");
                };
                let SendsOutcome::Accepted(accepted) = operator.accept_sends(request).unwrap()
                else {
                    panic!("the batch earned a report");
                };
                rpc::Response::Success {
                    body: accept_sends_response(vec![accepted[0].clone().into()]),
                }
            })
            .await;
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        assert!(
            agent
                .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                .await
                .is_err()
        );
        assert!(agent.pending_payments[0].acceptance.is_some());
        assert!(agent.pending_payments[1].acceptance.is_none());
        let expected = agent
            .pending_payments
            .iter()
            .map(|payment| payment.authorization.clone())
            .collect::<Vec<_>>();
        let (mut listener, mut operator) = partial.await.unwrap();

        // The operator cuts epoch 0 and registers epoch 1.
        let release = hold(&mut operator);
        let live = register(&control, &mut operator).await;

        // Every retry of the exact batch earns the lying report, and the wallet never reads a
        // head to re-sign.
        let lying = context.child("lying").spawn(move |_| async move {
            for _ in 0..crate::chain::client::SUBMIT_ATTEMPTS {
                respond_rpc(&mut listener, |request| {
                    let sent = sends(&operator_rpc::decode_request(request).unwrap());
                    assert_eq!(
                        sent.iter()
                            .map(|send| send.authorization.clone())
                            .collect::<Vec<_>>(),
                        expected
                    );
                    rpc::Response::Success {
                        body: empty_report(&live, 0),
                    }
                })
                .await;
            }
            (listener, operator)
        });
        let error = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("repeatedly rejected"));
        assert!(agent.superseded.is_empty());
        assert_eq!(agent.store.debits_since(0).unwrap(), 0);
        let (mut listener, mut operator) = lying.await.unwrap();

        // Epoch 0 is admitted carrying both sends. The exact batch replays both receipts, and
        // the sends conclude there.
        release_and_admit(&control, &mut operator, release, 0).await;
        let settled = context.child("settled").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
        });
        let outcomes = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap()
            .unwrap();
        settled.await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes
                .into_iter()
                .all(|outcome| accepted(outcome).epoch == 0)
        );
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert!(agent.pending_payments.is_empty());
    });
}

/// A report whose endpoint lies above every held receipt is usable only with the receipt for
/// the wallet's body at that endpoint.
///
/// The operator accepts the first of two sends and drops the reply, then cuts epoch 0. Its
/// report names the accepted first send. While the operator withholds that receipt, the
/// wallet retries the exact bytes. Once the receipt is served, the first send concludes in
/// epoch 0 and the second is re-signed under epoch 1 bound to the reported root.
#[test]
fn endpoint_above_held_receipts_requires_receipt() {
    for served in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(move |context| async move {
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();

            // The operator accepts only the first send, and the reply is lost.
            let partial = context.child("partial").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                let sent = sends(&drop_request(&mut listener).await);
                let SendsOutcome::Accepted(_) = operator
                    .accept_sends(operator_rpc::AcceptSendsRequest {
                        sends: vec![sent[0].clone()],
                    })
                    .unwrap()
                else {
                    panic!("the first send earned a report");
                };
                (listener, operator, sent)
            });
            let mut agent = Agent::new(0).unwrap();
            assert!(
                agent
                    .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                    .await
                    .is_err()
            );
            let (mut listener, mut operator, expected) = partial.await.unwrap();

            // The operator cuts epoch 0 and registers epoch 1.
            let _release = hold(&mut operator);
            register(&control, &mut operator).await;
            let reported = root(agent.account(), bob_edge(3, 1));

            // Each retry earns the report of the accepted first send, and the wallet asks for
            // its receipt. A served receipt lets the second send be re-signed under epoch 1.
            let rounds = if served {
                1
            } else {
                crate::chain::client::SUBMIT_ATTEMPTS
            };
            let script = context.child("script").spawn(move |_| async move {
                for _ in 0..rounds {
                    respond(&mut listener, |request| {
                        assert_eq!(sends(&request), expected);
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                    respond(&mut listener, |request| {
                        let operator_rpc::OperatorRequest::AcceptedBatch(fetch) = &request else {
                            panic!("expected a receipt fetch");
                        };
                        assert_eq!(fetch, &expected[0]);
                        if served {
                            operator_rpc::handle_decoded(&mut operator, request)
                        } else {
                            rpc::Response::Success {
                                body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                            }
                        }
                    })
                    .await;
                }
                if served {
                    relay(&mut listener, &mut operator).await;
                    respond(&mut listener, |request| {
                        let [send] = sends(&request).try_into().unwrap();
                        assert_eq!(send.authorization.body().epoch(), 1);
                        assert_eq!(send.authorization.predecessor(), reported);
                        operator_rpc::handle_decoded(&mut operator, request)
                    })
                    .await;
                }
            });
            let result = agent
                .resume_pending_payment(&context, &mut chain, address)
                .await;
            script.await.unwrap();

            // Without the receipt nothing concludes or is re-signed. With it, the first send
            // concludes in epoch 0 and the second in epoch 1.
            if served {
                let epochs = result
                    .unwrap()
                    .unwrap()
                    .into_iter()
                    .map(|outcome| accepted(outcome).epoch)
                    .collect::<Vec<_>>();
                assert_eq!(epochs, [0, 1]);
                assert_eq!(agent.store.debits_since(0).unwrap(), 7);
                assert!(agent.pending_payments.is_empty());
            } else {
                assert!(format!("{:#}", result.unwrap_err()).contains("repeatedly rejected"));
                assert_eq!(agent.store.debits_since(0).unwrap(), 0);
                assert!(
                    agent
                        .pending_payments
                        .iter()
                        .all(|payment| payment.acceptance.is_none()
                            && payment.authorization.body().epoch() == 0)
                );
                assert!(agent.superseded.is_empty());
            }
        });
    }
}

/// Silence is never exclusion.
///
/// After the cut, the operator drops every submission of the in-flight epoch-0 send without a
/// reply. The wallet keeps the exact bytes and signs nothing under epoch 1, although epoch 1
/// is registered. Once epoch 0 is admitted without the send, the wallet re-signs it under
/// epoch 1.
#[test]
fn silent_operator_keeps_waiting() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The first payment is receipted in epoch 0.
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

        // The operator cuts epoch 0 and registers epoch 1.
        let release = hold(&mut operator);
        let live = register(&control, &mut operator).await;

        // Three silent rounds resubmit the same epoch-0 bytes and resolve nothing.
        let mut expected = None;
        for _ in 0..3 {
            let silent = context.child("silent").spawn(move |_| async move {
                let request = drop_request(&mut listener).await;
                (listener, request)
            });
            assert!(
                agent
                    .pay(&context, &mut chain, address, &[(1, 3)])
                    .await
                    .is_err()
            );
            let (returned, request) = silent.await.unwrap();
            listener = returned;
            let [send] = sends(&request).try_into().unwrap();
            assert_eq!(send.authorization.body().epoch(), 0);
            assert_eq!(expected.get_or_insert(send.clone()), &send);
            assert_eq!(agent.pending_payments.len(), 1);
            assert!(agent.superseded.is_empty());
        }

        // Epoch 0 is admitted without the send, so the wallet re-signs it under epoch 1.
        release_and_admit(&control, &mut operator, release, 0).await;
        let rolling = context.child("rolling").spawn(move |_| async move {
            for _ in 0..3 {
                relay(&mut listener, &mut operator).await;
            }
        });
        let payment = accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 3)])
                .await
                .unwrap(),
        );
        rolling.await.unwrap();
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(
            payment.acceptance.ack.predecessor(),
            root(agent.account(), bob_edge(7, 1))
        );
        assert_eq!(agent.store.debits_since(0).unwrap(), 10);
    });
}

/// A retired predecessor admission decides nothing, so the pending send's own epoch resolves it.
///
/// The first payment is receipted in epoch 1, which the wallet keeps as its signing context.
/// Epochs 1 and 2 then finalize, which retires epoch 0's admission but keeps epoch 1's, and
/// epoch 3 is registered. The next payment is signed under the cached epoch 1 and misses it.
/// The wallet detects the retirement from the chain status, and epoch 1's finalized activity
/// excludes the send, so the wallet signs it again under epoch 3.
#[test]
fn retired_predecessor_admission_restages_stale_send() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let (control, mut chain) = super::chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let first = operator.complete_close(31).unwrap();
        finalize(&control, &first).await;
        let cached = register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The first payment reads the head and is receipted in epoch 1.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            (listener, operator)
        });
        let mut agent = Agent::new(0).unwrap();
        let receipted = accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(receipted.epoch, cached.epoch());
        let (mut listener, mut operator) = staging.await.unwrap();

        // Epochs 1 and 2 finalize, which retires epoch 0's admission and keeps epoch 1's, and
        // epoch 3 is registered.
        let second = operator.complete_close(32).unwrap();
        finalize(&control, &second).await;
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_some()
        );
        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let third = operator.complete_close(33).unwrap();
        finalize(&control, &third).await;
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_none()
        );
        assert!(
            control
                .record(admitted_key(&deployment(), 1))
                .await
                .is_some()
        );
        let live = register(&control, &mut operator).await;

        // The send signed under the cached epoch 1 resolves nothing at the operator, whose
        // epoch-1 vectors are retired too. After one head read, the wallet signs it again under
        // epoch 3.
        let rolling = context.child("rolling").spawn(move |_| async move {
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), cached.epoch());
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentHead(_)
                ));
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            relay(&mut listener, &mut operator).await;
        });
        let payment = accepted(
            agent
                .pay(&context, &mut chain, address, &[(1, 3)])
                .await
                .unwrap(),
        );
        rolling.await.unwrap();
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(payment.acceptance.ack.predecessor(), empty());
        assert_eq!(agent.store.debits_since(0).unwrap(), 10);
        assert!(agent.pending_payments.is_empty() && agent.superseded.is_empty());
    });
}

/// A payment re-signed into `e+1` is not signed again into `e+2` while its original in `e` is
/// undecided.
///
/// The original misses the epoch-0 cut, and its re-sign misses the epoch-1 cut. The epoch-1
/// report is empty and usable, but a body in epoch 2 pins only epoch 1, so the wallet waits
/// for epoch 0. Once epoch 0 is admitted without the original, the payment is signed under
/// epoch 2.
#[test]
fn resign_waits_for_original_epoch() {
    deterministic::Runner::timed(Duration::from_secs(40)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let cut_control = control.clone();

        // The original reaches the operator after the epoch-0 cut, and the re-sign after the
        // epoch-1 cut. The empty epoch-1 report is retried until the wallet gives up.
        let script = context.child("script").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let release = hold(&mut operator);
            register(&cut_control, &mut operator).await;
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), 0);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            relay(&mut listener, &mut operator).await;
            let (_, sink, mut stream) = listener.accept().await.unwrap();
            let resigned = sends(
                &operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap(),
            );
            operator.pay(2, 3, 1).unwrap();
            operator.start_close(1).unwrap();
            let successor = register(&cut_control, &mut operator).await;
            let mut sink = sink;
            rpc::send_response(
                &mut sink,
                &operator_rpc::handle_decoded(&mut operator, submission(resigned.clone())),
            )
            .await
            .unwrap();
            for _ in 1..crate::chain::client::SUBMIT_ATTEMPTS {
                respond(&mut listener, |request| {
                    assert_eq!(sends(&request), resigned);
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
            (listener, operator, release, resigned, successor)
        });
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, &mut chain, address, &[(1, 5)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("repeatedly rejected"));
        let (mut listener, mut operator, release, resigned, successor) = script.await.unwrap();
        let [resigned] = resigned.try_into().unwrap();
        assert_eq!(resigned.authorization.body().epoch(), 1);
        assert_eq!(resigned.authorization.predecessor(), empty());
        assert_eq!(agent.superseded.len(), 1);
        assert_eq!(agent.superseded[0].body().epoch(), 0);

        // Epoch 0 is admitted without the original, which decides it, so the payment is
        // signed under epoch 2 against the empty epoch-1 report.
        release_and_admit(&control, &mut operator, release, 0).await;
        let rolling = context.child("rolling").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), 2);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });
        let mut outcomes = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap()
            .unwrap();
        rolling.await.unwrap();
        let payment = accepted(outcomes.remove(0));
        assert_eq!(payment.epoch, successor.epoch());
        assert_eq!(payment.acceptance.ack.predecessor(), empty());
        assert_eq!(agent.store.debits_since(0).unwrap(), 5);
        assert!(agent.pending_payments.is_empty() && agent.superseded.is_empty());
    });
}

/// A nonempty report of the intermediate epoch does not lift the wait for the original epoch.
///
/// Two payments miss the epoch-0 cut and are re-signed into epoch 1, where the first is
/// accepted and the second misses the epoch-1 cut. The epoch-1 report names the accepted
/// first payment, so the root a body in epoch 2 would bind is nonempty. That root still pins
/// nothing in epoch 0, so the wallet waits until epoch 0 is admitted without the originals.
#[test]
fn resign_waits_despite_nonempty_intermediate_endpoint() {
    deterministic::Runner::timed(Duration::from_secs(40)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let cut_control = control.clone();

        // The originals miss the epoch-0 cut. The operator accepts only the first re-sign and
        // drops the reply.
        let script = context.child("script").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let release = hold(&mut operator);
            register(&cut_control, &mut operator).await;
            respond(&mut listener, |request| {
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            relay(&mut listener, &mut operator).await;
            let resigned = sends(&drop_request(&mut listener).await);
            let SendsOutcome::Accepted(_) = operator
                .accept_sends(operator_rpc::AcceptSendsRequest {
                    sends: vec![resigned[0].clone()],
                })
                .unwrap()
            else {
                panic!("the first re-sign earned a report");
            };
            (listener, operator, release, resigned)
        });
        let mut agent = Agent::new(0).unwrap();
        assert!(
            agent
                .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                .await
                .is_err()
        );
        let (mut listener, mut operator, release, resigned) = script.await.unwrap();
        assert!(
            resigned
                .iter()
                .all(|send| send.authorization.body().epoch() == 1)
        );
        assert_eq!(agent.superseded.len(), 2);

        // The operator cuts epoch 1 and registers epoch 2. The epoch-1 report names the first
        // re-sign, and every retry is the exact epoch-1 batch.
        operator.start_close(1).unwrap();
        let successor = register(&control, &mut operator).await;
        let expected = resigned.clone();
        let waiting = context.child("waiting").spawn(move |_| async move {
            for _ in 0..crate::chain::client::SUBMIT_ATTEMPTS {
                respond(&mut listener, |request| {
                    assert_eq!(sends(&request), expected);
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
            (listener, operator)
        });
        let error = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("repeatedly rejected"));
        let (mut listener, mut operator) = waiting.await.unwrap();
        assert_eq!(agent.superseded.len(), 2);

        // Epoch 0 is admitted without the originals while epoch 1's close stays held. The
        // first re-sign concludes in epoch 1 with its receipt, and the second is signed under
        // epoch 2 bound to its root.
        let (_started, _held) = operator.pause_next_close();
        let original = finish(&mut operator, release, 0);
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&original)),
        )
        .await;
        let intermediate = root(agent.account(), bob_edge(3, 1));
        let rolling = context.child("rolling").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), 2);
                assert_eq!(send.authorization.predecessor(), intermediate);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });
        let outcomes = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap()
            .unwrap();
        rolling.await.unwrap();
        let epochs = outcomes
            .into_iter()
            .map(|outcome| accepted(outcome).epoch)
            .collect::<Vec<_>>();
        assert_eq!(epochs, [1, successor.epoch()]);
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert!(agent.pending_payments.is_empty() && agent.superseded.is_empty());
    });
}

/// Bodies bound to a report that the admitted close contradicts are dead.
///
/// The operator carries the first of two payments in epoch 0 but reports an empty endpoint,
/// so the wallet re-signs both into epoch 1, where neither is accepted. Epoch 0's admission
/// shows the carried original: it concludes there with its receipt, and only the other
/// payment is signed again, under epoch 2, because the wallet signs nothing more in an epoch
/// whose bodies are dead.
#[test]
fn mismatched_predecessor_resigns_dead_bodies() {
    deterministic::Runner::timed(Duration::from_secs(40)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        operator.pay(2, 3, 1).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let cut_control = control.clone();

        // The operator carries only the first original, cuts epoch 0, and reports an empty
        // endpoint. The re-signed batch is dropped without a reply.
        let script = context.child("script").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let originals = sends(
                &operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap(),
            );
            let SendsOutcome::Accepted(_) = operator
                .accept_sends(operator_rpc::AcceptSendsRequest {
                    sends: vec![originals[0].clone()],
                })
                .unwrap()
            else {
                panic!("the first original earned a report");
            };
            let release = hold(&mut operator);
            let live = register(&cut_control, &mut operator).await;
            rpc::send_response(
                &mut sink,
                &rpc::Response::Success {
                    body: empty_report(&live, 0),
                },
            )
            .await
            .unwrap();
            relay(&mut listener, &mut operator).await;
            let resigned = sends(&drop_request(&mut listener).await);
            (listener, operator, release, resigned)
        });
        let mut agent = Agent::new(0).unwrap();
        assert!(
            agent
                .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                .await
                .is_err()
        );
        let (mut listener, mut operator, release, resigned) = script.await.unwrap();
        assert!(resigned.iter().all(|send| {
            send.authorization.body().epoch() == 1 && send.authorization.predecessor() == empty()
        }));
        assert_eq!(agent.superseded.len(), 2);

        // Epoch 0 is admitted carrying the first original. The wallet concludes it with its
        // receipt, but it cannot sign under epoch 1, whose bodies are dead.
        release_and_admit(&control, &mut operator, release, 0).await;
        let deciding = context.child("deciding").spawn(move |_| async move {
            for _ in 0..3 {
                relay(&mut listener, &mut operator).await;
            }
            (listener, operator)
        });
        let error = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("permanent settlement outcome"));
        let (mut listener, mut operator) = deciding.await.unwrap();
        assert_eq!(agent.store.debits_since(0).unwrap(), 3);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.superseded.is_empty());
        assert_eq!(agent.pending_payments.len(), 1);
        assert!(agent.pending_payments[0].replaceable);

        // Once epoch 1 is cut and epoch 2 registered, the remaining payment is signed under
        // epoch 2 bound to the empty root of the wallet's dead epoch-1 terminal.
        operator.pay(2, 3, 1).unwrap();
        operator.start_close(1).unwrap();
        operator.wait_for_closes().unwrap();
        let successor = register(&control, &mut operator).await;
        let rolling = context.child("rolling").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), 2);
                assert_eq!(send.authorization.predecessor(), empty());
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });
        let mut outcomes = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap()
            .unwrap();
        rolling.await.unwrap();
        let payment = accepted(outcomes.remove(0));
        assert_eq!(payment.epoch, successor.epoch());
        assert_eq!(payment.total, 4);
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert!(agent.pending_payments.is_empty());
    });
}

/// A receipt for a dead re-signed body that arrives after the contradicting admission does not
/// block the decision.
///
/// Two operator instances share one signing key. The carrier includes the first of two
/// originals in epoch 0, while the face reports an empty endpoint, so the wallet re-signs both
/// into epoch 1. Only after epoch 0 is admitted does the face receipt both re-signed bodies. The
/// carried original concludes with the carrier's receipt, the receipt of its dead re-sign stays
/// as evidence, and the other intent becomes replaceable with its receipt. A reopened store
/// counts the same receipts.
#[test]
fn late_resign_receipt_settles_carried_original() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let mut carrier = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut face = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut face).await;
        carrier
            .adopt_registration(&registration_record(&control).await)
            .unwrap();
        carrier.pay(2, 3, 1).unwrap();
        face.pay(2, 3, 1).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let cut_control = control.clone();

        // The carrier accepts only the first original. The face cuts epoch 0 and reports an
        // empty endpoint, and the re-signed batch is dropped without a reply.
        let script = context.child("script").spawn(move |_| async move {
            relay(&mut listener, &mut face).await;
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let originals = sends(
                &operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap(),
            );
            let SendsOutcome::Accepted(_) = carrier
                .accept_sends(operator_rpc::AcceptSendsRequest {
                    sends: vec![originals[0].clone()],
                })
                .unwrap()
            else {
                panic!("the carrier refused the first original");
            };
            let release = hold(&mut face);
            let live = register(&cut_control, &mut face).await;
            rpc::send_response(
                &mut sink,
                &rpc::Response::Success {
                    body: empty_report(&live, 0),
                },
            )
            .await
            .unwrap();
            relay(&mut listener, &mut face).await;
            drop_request(&mut listener).await;
            (listener, face, carrier, release)
        });
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert!(
            agent
                .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                .await
                .is_err()
        );
        let (mut listener, mut face, mut carrier, _release) = script.await.unwrap();
        assert_eq!(agent.superseded.len(), 2);

        // Epoch 0 is admitted carrying the first original.
        carrier.start_close(0).unwrap();
        carrier.wait_for_closes().unwrap();
        let original = carrier.retained_result(0).unwrap().unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&original)),
        )
        .await;

        // The face now receipts both re-signed bodies, and the carrier serves the carried
        // original's receipt. The remaining intent cannot be signed under epoch 1.
        let deciding = context.child("deciding").spawn(move |_| async move {
            relay(&mut listener, &mut face).await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptedBatch(_)
                ));
                operator_rpc::handle_decoded(&mut carrier, request)
            })
            .await;
            relay(&mut listener, &mut face).await;
        });
        let error = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap_err();
        deciding.await.unwrap();
        assert!(format!("{error:#}").contains("permanent settlement outcome"));
        assert_eq!(agent.store.debits_since(0).unwrap(), 3);
        assert_eq!(agent.receipt_count(), 2);
        assert!(agent.superseded.is_empty());
        let [remaining] = agent.pending_payments.as_slice() else {
            panic!("one intent remains");
        };
        assert!(remaining.replaceable && remaining.acceptance.is_some());
        assert_eq!(remaining.authorization.body().epoch(), 1);

        // A reopened wallet holds the same receipts and the same replaceable intent.
        drop(agent);
        let agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(agent.receipt_count(), 2);
        assert!(agent.superseded.is_empty());
        let [remaining] = agent.pending_payments.as_slice() else {
            panic!("one intent remains after reopening");
        };
        assert!(remaining.replaceable && remaining.acceptance.is_some());
    });
}

/// A batch bound to a receipted endpoint that its admitted predecessor contradicts is decided
/// without superseded copies.
///
/// Two operator instances share one signing key. The face accepts both sends of a batch while
/// the carrier accepts only the first, and a usable report of the face's endpoint concludes
/// both in epoch 0. The next payment is signed fresh under epoch 1, bound to that endpoint, and
/// dropped. Once the carrier's epoch-0 close is admitted, no close can carry it, so it becomes
/// replaceable and the wallet refuses to sign again under epoch 1.
#[test]
fn mismatched_predecessor_without_resign_is_replaceable() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut carrier = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut face = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut face).await;
        carrier
            .adopt_registration(&registration_record(&control).await)
            .unwrap();
        carrier.pay(2, 3, 1).unwrap();
        face.pay(2, 3, 1).unwrap();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();

        // The face accepts both sends and the carrier only the first. The reply is lost.
        let partial = context.child("partial").spawn(move |_| async move {
            relay(&mut listener, &mut face).await;
            let sent = sends(&drop_request(&mut listener).await);
            let SendsOutcome::Accepted(_) = face
                .accept_sends(operator_rpc::AcceptSendsRequest {
                    sends: sent.clone(),
                })
                .unwrap()
            else {
                panic!("the face refused the batch");
            };
            let SendsOutcome::Accepted(_) = carrier
                .accept_sends(operator_rpc::AcceptSendsRequest {
                    sends: vec![sent[0].clone()],
                })
                .unwrap()
            else {
                panic!("the carrier refused the first send");
            };
            (listener, face, carrier)
        });
        let mut agent = Agent::new(0).unwrap();
        assert!(
            agent
                .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                .await
                .is_err()
        );
        let (mut listener, mut face, mut carrier) = partial.await.unwrap();

        // The face cuts epoch 0 and reports the batch endpoint. With both receipts served,
        // the batch concludes in epoch 0.
        let _release = hold(&mut face);
        let live = register(&control, &mut face).await;
        let mut endpoint = vec![
            OutEntry {
                recipient: wallets()[1].public_key(),
                cumulative: 3,
                count: 1,
            },
            OutEntry {
                recipient: wallets()[2].public_key(),
                cumulative: 4,
                count: 1,
            },
        ];
        endpoint.sort_by(|left, right| left.recipient.cmp(&right.recipient));
        let report = operator_rpc::AcceptSendsResponse::Stale(operator_rpc::StaleResponse {
            context: live,
            epoch: 0,
            cumulative_debit: 7,
            seq: 2,
            predecessor: root(agent.account(), endpoint.clone()),
            entries: endpoint,
        })
        .encode();
        let concluding = context.child("concluding").spawn(move |_| async move {
            respond(&mut listener, |_| rpc::Response::Success { body: report }).await;
            for _ in 0..2 {
                relay(&mut listener, &mut face).await;
            }
            (listener, face)
        });
        let outcomes = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap()
            .unwrap();
        let (mut listener, mut face) = concluding.await.unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);

        // The next payment reads the epoch-1 head, binds the concluded endpoint, and is
        // dropped.
        let staging = context.child("staging").spawn(move |_| async move {
            relay(&mut listener, &mut face).await;
            let [send] = sends(&drop_request(&mut listener).await)
                .try_into()
                .unwrap();
            (listener, face, send)
        });
        assert!(
            agent
                .pay(&context, &mut chain, address, &[(1, 5)])
                .await
                .is_err()
        );
        let (mut listener, mut face, send) = staging.await.unwrap();
        assert_eq!(send.authorization.body().epoch(), 1);
        assert_ne!(send.authorization.predecessor(), empty());
        assert!(agent.superseded.is_empty());

        // Epoch 0 is admitted carrying only the first send. The pending send becomes
        // replaceable, and the wallet refuses to sign again under epoch 1.
        carrier.start_close(0).unwrap();
        carrier.wait_for_closes().unwrap();
        let original = carrier.retained_result(0).unwrap().unwrap();
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&original)),
        )
        .await;
        let deciding = context.child("deciding").spawn(move |_| async move {
            drop_request(&mut listener).await;
            relay(&mut listener, &mut face).await;
        });
        let error = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap_err();
        deciding.await.unwrap();
        assert!(format!("{error:#}").contains("permanent settlement outcome"));
        assert_eq!(agent.store.debits_since(0).unwrap(), 7);
        assert!(agent.superseded.is_empty());
        let [remaining] = agent.pending_payments.as_slice() else {
            panic!("one intent remains");
        };
        assert!(remaining.replaceable);
        assert_eq!(remaining.authorization, send.authorization);
    });
}

/// A lying operator's admitted epoch-1 close that omits a re-sign it receipted.
struct Omitted {
    control: harness::Control,
    chain: Client,
    agent: Agent,
    carrier: Operator,
    original: SettlementResult,
    omitting: SettlementResult,
    protocol: Protocol,
    _face: Operator,
    _release: SyncSender<()>,
}

/// Admits a lying operator's epoch-1 close that omits a re-sign it receipted.
///
/// Two operator instances share one signing key. The carrier includes the original in epoch
/// 0, while the operator the wallet talks to reports an empty endpoint and receipts the
/// re-sign in epoch 1. The carrier refuses the re-sign, validators refuse any epoch-1 close
/// carrying it, and the carrier's epoch-1 close omits it and is admitted.
async fn omit_resign(context: &deterministic::Context, timing: crate::protocol::Timing) -> Omitted {
    let (control, mut chain) = chain_with(context, timing).await;
    let mut carrier = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
    let mut face = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
    register(&control, &mut face).await;
    carrier
        .adopt_registration(&registration_record(&control).await)
        .unwrap();
    carrier.pay(2, 3, 1).unwrap();
    face.pay(2, 3, 1).unwrap();
    let mut listener = context
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let cut_control = control.clone();

    // The carrier accepts the original in epoch 0. The face cuts epoch 0, reports the
    // payer's empty epoch-0 endpoint, and receipts the re-sign in epoch 1.
    let script = context.child("script").spawn(move |_| async move {
        relay(&mut listener, &mut face).await;
        let (_, mut sink, mut stream) = listener.accept().await.unwrap();
        let request =
            operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap()).unwrap();
        let [original] = sends(&request).try_into().unwrap();
        carrier
            .accept_sends(operator_rpc::AcceptSendsRequest {
                sends: vec![original],
            })
            .unwrap();
        let release = hold(&mut face);
        register(&cut_control, &mut face).await;
        rpc::send_response(&mut sink, &operator_rpc::handle_decoded(&mut face, request))
            .await
            .unwrap();
        relay(&mut listener, &mut face).await;
        relay(&mut listener, &mut face).await;
        (face, carrier, release)
    });
    let mut agent = Agent::new(0).unwrap();
    let resigned = accepted(
        agent
            .pay(context, &mut chain, address, &[(1, 5)])
            .await
            .unwrap(),
    );
    let (face, mut carrier, release) = script.await.unwrap();
    assert_eq!(resigned.epoch, 1);
    assert_eq!(resigned.acceptance.ack.predecessor(), empty());

    // Epoch 0 is admitted carrying the original.
    carrier.start_close(0).unwrap();
    carrier.wait_for_closes().unwrap();
    let original = carrier.retained_result(0).unwrap().unwrap();
    applied(
        &control,
        &SettlementTx::Admit(AdmitRequest::from(&original)),
    )
    .await;

    // The carrier refuses the re-sign, and validators refuse any epoch-1 close carrying
    // it.
    let successor = registration_record(&control).await;
    carrier.adopt_registration(&successor).unwrap();
    let ack = &resigned.acceptance.ack;
    let authorization = SendAuthorization::from_raw_unchecked(
        ack.body().clone(),
        ack.predecessor(),
        ack.payer_signature().clone(),
    );
    let entries = vec![Entry {
        recipient: wallets()[1].public_key(),
        amount: 5,
    }];
    assert!(matches!(
        carrier
            .accept_sends(operator_rpc::AcceptSendsRequest {
                sends: vec![operator_rpc::AcceptSendRequest {
                    authorization: authorization.clone(),
                    entries,
                }],
            })
            .unwrap(),
        SendsOutcome::Stale { .. }
    ));
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let mut registration = protocol
        .registration(
            1,
            DepositBatch::empty(),
            WithdrawalBatch::empty(),
            original.context.predecessor_liability(),
        )
        .unwrap();
    registration.floors = Some(successor.floors);
    registration.deadlines = successor.deadlines;
    let terminal = Terminal {
        operator_signature: protocol.sign_ack_aggregate(&authorization),
        authorization,
        vector: OutVector::new(1, agent.account(), bob_edge(5, 1)).unwrap(),
    };
    let prepared = protocol.prepare(registration, vec![terminal]).unwrap();
    assert!(
        protocol
            .fixture_complete(
                &crate::protocol::accounts(),
                std::slice::from_ref(&original),
                prepared,
                7,
            )
            .is_err()
    );

    // The carrier's epoch-1 close omits the re-sign and is admitted.
    carrier.pay(2, 3, 1).unwrap();
    carrier.start_close(1).unwrap();
    carrier.wait_for_closes().unwrap();
    let omitting = carrier.retained_result(1).unwrap().unwrap();
    applied(
        &control,
        &SettlementTx::Admit(AdmitRequest::from(&omitting)),
    )
    .await;
    Omitted {
        control,
        chain,
        agent,
        carrier,
        original,
        omitting,
        protocol,
        _face: face,
        _release: release,
    }
}

/// A lying operator cannot settle a re-signed payment beside the original it carried.
///
/// After the lying operator's epoch-1 close omits the receipted re-sign, the wallet's
/// challenge watcher convicts it with a proven `HigherAckDebit` challenge from that receipt.
/// The payer is debited once.
#[test]
fn lying_operator_cannot_settle_resign_after_carrying_original() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let Omitted {
            control,
            mut chain,
            mut agent,
            original,
            protocol,
            ..
        } = Box::pin(omit_resign(
            &context,
            crate::protocol::Timing {
                admission_offset: 1_000,
                challenge_duration: 8,
            },
        ))
        .await;

        // The wallet's challenge watcher convicts the omitting close with its receipt.
        let admitted = chain.admitted(&context, 1).await.unwrap().unwrap();
        assert_eq!(agent.enforce(&context, &mut chain).await.unwrap(), [1]);
        assert!(matches!(
            control.record(fault_key(&deployment())).await,
            Some(Record::Fault(FaultRecord::Faulted(
                HardFaultReasonResponse::ProvenChallenge {
                    batch_id,
                    kind: ChallengeKind::HigherAckDebit,
                }
            ))) if batch_id == admitted.batch_id
        ));

        // The payer is debited once: epoch 0 carried the original, and nothing else settles.
        assert_eq!(
            protocol
                .fixture_opening(
                    &crate::protocol::accounts(),
                    std::slice::from_ref(&original),
                    &agent.account(),
                )
                .unwrap()
                .balance
                .get(),
            INITIAL_BALANCE - 5
        );
        assert_eq!(agent.store.debits_since(0).unwrap(), 5);
    });
}

/// An unrelated fault does not stop the watcher from convicting a surviving close.
///
/// After the lying operator's epoch-1 close omits the receipted re-sign, the carrier registers
/// epoch 2 and lets its admission deadline pass. That faults the deployment with an expired
/// registration while epoch 1 is still challengeable, and the watcher still challenges epoch 1
/// with its receipt. The fault keeps its first reason, so the conviction shows once terminal
/// settlement begins: epoch 1 starts the invalid suffix and epoch 0's root is frozen.
#[test]
fn watcher_convicts_a_surviving_close_after_an_unrelated_fault() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let Omitted {
            control,
            mut chain,
            mut agent,
            mut carrier,
            original,
            omitting,
            ..
        } = Box::pin(omit_resign(
            &context,
            crate::protocol::Timing {
                admission_offset: 50,
                challenge_duration: 100,
            },
        ))
        .await;
        let admitted = chain.admitted(&context, 1).await.unwrap().unwrap();

        // Epoch 2 registers as the frontier and expires inside epoch 1's challenge window.
        register(&control, &mut carrier).await;
        let (admission, _) = registration_record(&control).await.deadlines.unwrap();
        let height = control.advance(0).await;
        let height = control.advance(admission - height + 1).await;
        assert!(height <= omitting.context.challenge_deadline());
        assert!(matches!(
            chain.fault(&context).await.unwrap(),
            Some(FaultRecord::Faulted(
                HardFaultReasonResponse::ExpiredRegistration { .. }
            ))
        ));

        // The watcher challenges epoch 1, and the fault keeps its first reason.
        assert!(
            agent
                .enforce(&context, &mut chain)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            chain.fault(&context).await.unwrap(),
            Some(FaultRecord::Faulted(
                HardFaultReasonResponse::ExpiredRegistration { .. }
            ))
        ));

        // Epoch 0 finalizes, and terminal settlement starts the invalid suffix at epoch 1.
        let height = control.advance(0).await;
        control
            .advance(original.context.challenge_deadline() - height + 1)
            .await;
        control
            .submit(SettlementTx::BeginHardFaultSettlement(
                BeginHardFaultSettlementRequest {
                    deployment: deployment(),
                },
            ))
            .await;
        let Some(FaultRecord::Settling(settlement)) = chain.fault(&context).await.unwrap() else {
            panic!("terminal settlement began");
        };
        assert_eq!(settlement.invalid_from, Some(admitted.batch_id));
        assert_eq!(settlement.frozen_state_root, original.roots.successor);
    });
}

/// A wallet away from before its original epoch's admission until after the successor
/// finalizes still decides its superseded copies.
///
/// The original misses the epoch-0 cut, and the wallet re-signs it under epoch 1 against the
/// empty report, but the re-sign is lost and the wallet goes away. Epochs 0 and 1 are admitted
/// without either copy and both finalize. The chain still retains epoch 0's admission, so a
/// failed read of it is not retirement: it decides nothing and leaves the batch unchanged. With
/// the read served, the returning wallet proves the original uncarried, concludes the re-sign
/// as excluded from the finalized epoch-1 close, and signs the payment once under epoch 2.
#[test]
fn offline_wallet_decides_superseded_copies_after_successor_finality() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let (control, mut chain) = chain(&context).await;
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        register(&control, &mut operator).await;
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let cut_control = control.clone();

        // The original misses the epoch-0 cut and earns the empty report. The re-sign under
        // epoch 1 is lost.
        let script = context.child("script").spawn(move |_| async move {
            relay(&mut listener, &mut operator).await;
            let release = hold(&mut operator);
            register(&cut_control, &mut operator).await;
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), 0);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            relay(&mut listener, &mut operator).await;
            let resigned = sends(&drop_request(&mut listener).await);
            (listener, operator, release, resigned)
        });
        let mut agent = Agent::new(0).unwrap();
        assert!(
            agent
                .pay(&context, &mut chain, address, &[(1, 5)])
                .await
                .is_err()
        );
        let (mut listener, mut operator, release, resigned) = script.await.unwrap();
        let [resigned] = resigned.try_into().unwrap();
        assert_eq!(resigned.authorization.body().epoch(), 1);
        assert_eq!(agent.superseded.len(), 1);

        // While the wallet is away, epoch 0 is admitted without the original. Epoch 1, promoted
        // at that admission, is admitted without the re-sign, and both epochs finalize.
        let original = finish(&mut operator, release, 0);
        applied(
            &control,
            &SettlementTx::Admit(AdmitRequest::from(&original)),
        )
        .await;
        operator
            .adopt_registration(&registration_record(&control).await)
            .unwrap();
        operator.pay(2, 3, 1).unwrap();
        operator.start_close(1).unwrap();
        operator.wait_for_closes().unwrap();
        let excluding = operator.retained_result(1).unwrap().unwrap();
        finalize(&control, &excluding).await;
        let live = register(&control, &mut operator).await;
        assert!(
            control
                .record(admitted_key(&deployment(), 0))
                .await
                .is_some()
        );

        // A refused read of the retained epoch-0 admission is not retirement, so the returning
        // wallet decides nothing and keeps both copies unchanged.
        let expected = resigned.clone();
        let refusing = context.child("refusing").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert_eq!(sends(&request), [expected]);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            (listener, operator)
        });
        let query = SocketAddr::from(([127, 0, 0, 1], 9_712));
        super::query_refusing_admission(&context, query, 0).await;
        let mut refused = client_with_query_and_holders(&context, &control, query, CHAIN);
        let error = agent
            .resume_pending_payment(&context, &mut refused, address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("read the admitted predecessor"));
        let (mut listener, mut operator) = refusing.await.unwrap();
        assert_eq!(agent.pending_payments.len(), 1);
        assert!(!agent.pending_payments[0].replaceable);
        assert_eq!(agent.superseded.len(), 1);

        // With the read served, the wallet decides both copies and signs the payment under
        // epoch 2.
        let rolling = context.child("rolling").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert_eq!(sends(&request), [resigned]);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            relay(&mut listener, &mut operator).await;
            respond(&mut listener, |request| {
                let [send] = sends(&request).try_into().unwrap();
                assert_eq!(send.authorization.body().epoch(), 2);
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });
        let mut outcomes = agent
            .resume_pending_payment(&context, &mut chain, address)
            .await
            .unwrap()
            .unwrap();
        rolling.await.unwrap();
        let payment = accepted(outcomes.remove(0));
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(payment.acceptance.ack.predecessor(), empty());
        assert_eq!(agent.store.debits_since(0).unwrap(), 5);
        assert!(agent.pending_payments.is_empty() && agent.superseded.is_empty());
    });
}

/// A pending batch whose epoch is final concludes without receipts from the finalized close the
/// chain retains after the successor finalizes.
///
/// The send is staged in epoch 0 and its reply is lost, with the operator accepting it only when
/// `carried`. While the wallet is away, epochs 0 and 1 both finalize. The returning wallet's
/// operator refuses every request that could serve a receipt, so only epoch 0's retained
/// admission and rows decide the send: a carried send concludes as committed without receipts,
/// and an excluded one is signed again under epoch 2.
#[test]
fn offline_pending_batch_concludes_from_finalized_close() {
    for carried in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(60)).start(move |context| async move {
            let (control, mut chain) = chain(&context).await;
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            register(&control, &mut operator).await;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();

            // The send reads the head and is staged in epoch 0. Its reply is lost, and the
            // operator accepts it only when it is carried.
            let staging = context.child("staging").spawn(move |_| async move {
                relay(&mut listener, &mut operator).await;
                if carried {
                    accept_and_drop(&mut listener, &mut operator).await;
                } else {
                    drop_request(&mut listener).await;
                }
                (listener, operator)
            });
            let mut agent = Agent::new(0).unwrap();
            assert!(
                agent
                    .pay(&context, &mut chain, address, &[(1, 5)])
                    .await
                    .is_err()
            );
            let (mut listener, mut operator) = staging.await.unwrap();

            // While the wallet is away, epochs 0 and 1 finalize. The chain still retains epoch
            // 0's anchor and admission.
            let first = operator.complete_close(31).unwrap();
            finalize(&control, &first).await;
            register(&control, &mut operator).await;
            operator.pay(2, 3, 1).unwrap();
            let second = operator.complete_close(32).unwrap();
            finalize(&control, &second).await;
            let live = register(&control, &mut operator).await;
            assert!(control.record(anchor_key(&deployment(), 0)).await.is_some());
            assert!(
                control
                    .record(admitted_key(&deployment(), 0))
                    .await
                    .is_some()
            );

            // The operator refuses the exact bytes and every receipt, so epoch 0's retained
            // close decides the send.
            let script = context.child("script").spawn(move |_| async move {
                refuse(&mut listener).await;
                if carried {
                    refuse(&mut listener).await;
                } else {
                    relay(&mut listener, &mut operator).await;
                    relay(&mut listener, &mut operator).await;
                }
            });
            let outcomes = agent
                .resume_pending_payment(&context, &mut chain, address)
                .await
                .unwrap()
                .unwrap();
            script.await.unwrap();
            match (carried, outcomes.as_slice()) {
                (true, [PaymentOutcome::CommittedUnheld { epoch: 0, total: 5 }]) => {}
                (false, [PaymentOutcome::Accepted(payment)]) => {
                    assert_eq!(payment.epoch, live.epoch());
                }
                (_, outcomes) => panic!("unexpected payment outcomes: {outcomes:?}"),
            }
            assert_eq!(agent.store.debits_since(0).unwrap(), 5);
            assert!(agent.pending_payments.is_empty());
        });
    }
}

/// The wallet's challenge watcher convicts a close that omits an acknowledged send it can no
/// longer carry, and prunes those receipts once they cannot prove anything.
///
/// Two operator instances share one signing key. The carrier includes the first of two
/// originals in epoch 0, while the face reports an empty endpoint, so the wallet re-signs both
/// into epoch 1, and the face receipts both only after epoch 0 is admitted. The wallet keeps the
/// dead re-sign's receipt as evidence. The carrier's epoch-1 close omits both re-signs and is
/// admitted. When the watcher runs inside the challenge window it proves `HigherAckDebit`, and
/// its next pass prunes the dead receipt. When the close finalizes first, the watcher submits
/// nothing and prunes the receipt.
#[test]
fn watcher_convicts_omitting_close_and_prunes_dead_receipts() {
    for late in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(60)).start(move |context| async move {
            let (control, mut chain) = chain(&context).await;
            let mut carrier = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut face = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            register(&control, &mut face).await;
            carrier
                .adopt_registration(&registration_record(&control).await)
                .unwrap();
            carrier.pay(2, 3, 1).unwrap();
            face.pay(2, 3, 1).unwrap();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let cut_control = control.clone();

            // The carrier accepts only the first original. The face cuts epoch 0 and reports an
            // empty endpoint, and the re-signed batch is dropped without a reply.
            let script = context.child("script").spawn(move |_| async move {
                relay(&mut listener, &mut face).await;
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let originals = sends(
                    &operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                        .unwrap(),
                );
                let SendsOutcome::Accepted(_) = carrier
                    .accept_sends(operator_rpc::AcceptSendsRequest {
                        sends: vec![originals[0].clone()],
                    })
                    .unwrap()
                else {
                    panic!("the carrier refused the first original");
                };
                let release = hold(&mut face);
                let live = register(&cut_control, &mut face).await;
                rpc::send_response(
                    &mut sink,
                    &rpc::Response::Success {
                        body: empty_report(&live, 0),
                    },
                )
                .await
                .unwrap();
                relay(&mut listener, &mut face).await;
                drop_request(&mut listener).await;
                (listener, face, carrier, release)
            });
            let mut agent = Agent::new(0).unwrap();
            assert!(
                agent
                    .pay_batch(&context, &mut chain, address, &[vec![(1, 3)], vec![(2, 4)]])
                    .await
                    .is_err()
            );
            let (mut listener, mut face, mut carrier, _release) = script.await.unwrap();

            // Epoch 0 is admitted carrying the first original. The face then receipts both
            // re-signs, the carried original concludes, and the dead re-sign keeps its receipt.
            carrier.start_close(0).unwrap();
            carrier.wait_for_closes().unwrap();
            let original = carrier.retained_result(0).unwrap().unwrap();
            applied(
                &control,
                &SettlementTx::Admit(AdmitRequest::from(&original)),
            )
            .await;
            let deciding = context.child("deciding").spawn(move |_| async move {
                relay(&mut listener, &mut face).await;
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::AcceptedBatch(_)
                    ));
                    operator_rpc::handle_decoded(&mut carrier, request)
                })
                .await;
                relay(&mut listener, &mut face).await;
                carrier
            });
            assert!(
                agent
                    .resume_pending_payment(&context, &mut chain, address)
                    .await
                    .is_err()
            );
            let mut carrier = deciding.await.unwrap();
            assert_eq!(agent.receipt_count(), 2);

            // The carrier's epoch-1 close omits both re-signs and is admitted.
            carrier
                .adopt_registration(&registration_record(&control).await)
                .unwrap();
            carrier.pay(2, 3, 1).unwrap();
            carrier.start_close(1).unwrap();
            carrier.wait_for_closes().unwrap();
            let omitting = carrier.retained_result(1).unwrap().unwrap();
            let batch_id = omitting.header.batch_id::<Sha256>();
            if late {
                // The omitting close finalizes before the watcher runs, so the receipt proves
                // nothing and is pruned without a challenge.
                finalize(&control, &omitting).await;
                assert!(
                    agent
                        .enforce(&context, &mut chain)
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert!(control.record(fault_key(&deployment())).await.is_none());
            } else {
                // Inside the challenge window the watcher convicts the omitting close.
                applied(
                    &control,
                    &SettlementTx::Admit(AdmitRequest::from(&omitting)),
                )
                .await;
                assert_eq!(agent.enforce(&context, &mut chain).await.unwrap(), [1]);
                assert!(matches!(
                    control.record(fault_key(&deployment())).await,
                    Some(Record::Fault(FaultRecord::Faulted(
                        HardFaultReasonResponse::ProvenChallenge {
                            batch_id: proven,
                            kind: ChallengeKind::HigherAckDebit,
                        }
                    ))) if proven == batch_id
                ));
                assert_eq!(agent.receipt_count(), 2);

                // The invalidated close can no longer be challenged, so the next pass prunes.
                assert!(
                    agent
                        .enforce(&context, &mut chain)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }

            // Only the carried original's receipt remains in the ledger.
            assert_eq!(agent.receipt_count(), 1);
            assert!(
                agent
                    .enforce(&context, &mut chain)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(agent.receipt_count(), 1);
        });
    }
}

/// A receipt verifies with the predecessor it carries.
///
/// The recipient stores that predecessor across a reopen and passes it into its challenge
/// witness. A copy whose predecessor differs from the countersigned one fails verification
/// and never becomes held credit.
#[test]
fn receipt_verifies_with_carried_predecessor() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let (control, mut chain) = chain(&context).await;
        let payment = registered_context(&control).await.payment().clone();
        let payer = wallets().remove(0);
        let recipient = wallets()[1].public_key();
        let predecessor = VectorRoot {
            digest: Sha256::hash(&[b"payer-preceding-terminal"]),
        };

        // The genuine receipt countersigns the predecessor. The forged copy carries another
        // predecessor under the same signatures.
        let vector = OutVector::new(0, payer.public_key(), bob_edge(5, 1)).unwrap();
        let body = VectorSendBody::new(
            &payment,
            payer.public_key(),
            1,
            5,
            vector.root::<Sha256, Digest>().unwrap(),
        );
        let ack = Ack::sign_by_authorities(
            body,
            predecessor,
            payer.signer(),
            Protocol::new(NonZeroUsize::MIN).unwrap().operator(),
        );
        let OutTipLookup::Present { opening, .. } =
            vector.lookup::<Sha256, Digest>(&recipient).unwrap()
        else {
            panic!("the credited entry is present by construction");
        };
        let genuine = Receipt {
            ack: ack.clone(),
            recipient,
            cumulative: 5,
            count: 1,
            opening,
        };
        let forged = Receipt {
            ack: Ack::from_raw_unchecked(
                ack.body().clone(),
                empty(),
                ack.payer_signature().clone(),
                ack.operator_signature().clone(),
            ),
            ..genuine.clone()
        };
        assert!(genuine.verify::<Sha256>(&payment).is_ok());
        assert!(forged.verify::<Sha256>(&payment).is_err());

        // The operator serves both, and the recipient holds only the genuine receipt.
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let page = incoming_response(&[(forged, 1), (genuine.clone(), 2)]);
        let server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: page.encode(),
                }
            })
            .await;
        });
        let mut recipient = Agent::open(database.path(), 1).unwrap();
        recipient
            .intake_incoming(&context, &mut chain, address)
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(recipient.incoming().count, 1);
        assert_eq!(recipient.incoming().cursor, 2);

        // The held receipt keeps its predecessor across a reopen, and the witness carries it.
        drop(recipient);
        let recipient = Agent::open(database.path(), 1).unwrap();
        let held = recipient.store.held_receipts(0, &operator_key()).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].receipt, genuine);
        assert_eq!(
            AckWitness::from_ack(&held[0].receipt.ack).predecessor,
            predecessor
        );
    });
}
