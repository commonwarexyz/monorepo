//! Bounded operator RPC intake and payment scheduling.

use super::register_epoch;
use crate::{
    chain::client::{Chain, Env},
    operator::{
        MAX_VERIFICATION_BATCHES, Operator, SendsOutcome, VerifiedSends, rpc as operator_rpc,
        verify_sends,
    },
    protocol::Key,
    rpc,
};
use anyhow::{Result, ensure};
use commonware_codec::Encode as _;
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Listener, Spawner};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use futures::{FutureExt as _, StreamExt as _, stream::FuturesUnordered};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    sync::Arc,
};

const MAX_CONNECTIONS: usize = 32;
const MAX_PENDING_BATCHES: usize = 32;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Serves bounded one-request connections concurrently.
pub(super) async fn serve_connections<E, L, F, Fut>(context: E, listener: L, handler: F)
where
    E: Clock + Spawner,
    L: Listener,
    F: Fn(rpc::Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = rpc::Response> + Send + 'static,
{
    serve_connections_inner(context, listener, handler, |_| {}).await;
}

#[cfg(test)]
pub(super) async fn serve_connections_with_completion<E, L, F, Fut>(
    context: E,
    listener: L,
    handler: F,
    completed: std::sync::mpsc::SyncSender<bool>,
) where
    E: Clock + Spawner,
    L: Listener,
    F: Fn(rpc::Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = rpc::Response> + Send + 'static,
{
    serve_connections_inner(context, listener, handler, move |sent| {
        let _ = completed.send(sent);
    })
    .await;
}

async fn serve_connections_inner<E, L, F, Fut, C>(
    context: E,
    mut listener: L,
    handler: F,
    completed: C,
) where
    E: Clock + Spawner,
    L: Listener,
    F: Fn(rpc::Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = rpc::Response> + Send + 'static,
    C: Fn(bool) + Clone + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let mut connections = FuturesUnordered::<Handle<()>>::new();
    loop {
        while let Some(Some(result)) = connections.next().now_or_never() {
            result.expect("operator RPC connection task failed");
        }
        let accepted = select! {
            result = async {
                if connections.is_empty() {
                    std::future::pending().await
                } else {
                    connections.next().await
                }
            } => {
                result
                    .expect("connection exists")
                    .expect("operator RPC connection task failed");
                continue;
            },
            accepted = listener.accept() => accepted,
        };
        let (_, mut sink, mut stream) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("accept operator RPC failed; retrying: {error}");
                context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        if connections.len() >= MAX_CONNECTIONS {
            continue;
        }
        let handler = Arc::clone(&handler);
        let completed = completed.clone();
        connections.push(
            context
                .child("connection")
                .spawn(move |context| async move {
                    let request = select! {
                        request = rpc::recv_request(&mut stream) => request,
                        _ = context.sleep(REQUEST_TIMEOUT) => return,
                    };
                    let Ok(request) = request else { return };
                    let response = handler(request).await;
                    let sent = select! {
                        result = rpc::send_response(&mut sink, &response) => result.is_ok(),
                        _ = context.sleep(REQUEST_TIMEOUT) => false,
                    };
                    drop(sink);
                    drop(stream);
                    completed(sent);
                }),
        );
    }
}

#[derive(Clone, Copy)]
pub(super) enum ResponseKind {
    Single,
    Batch,
}

struct Payment {
    request: operator_rpc::AcceptSendsRequest,
    kind: ResponseKind,
    response: oneshot::Sender<rpc::Response>,
}

#[derive(Clone)]
pub(super) struct PaymentSender(mpsc::Sender<Payment>);

struct VerifiedGroup {
    payments: Vec<Payment>,
    verified: Vec<Result<VerifiedSends>>,
}

struct CompletedGroup {
    responses: Vec<(usize, Payment, rpc::Response)>,
    fatal: Option<String>,
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestHooks {
    pub(super) verifier_started: std::sync::mpsc::SyncSender<()>,
    pub(super) verifier_finished: std::sync::mpsc::SyncSender<()>,
}

pub(super) fn start<E, C>(
    context: E,
    chain: C,
    operator: Arc<Mutex<Operator>>,
    strategy: commonware_parallel::Rayon,
) -> (PaymentSender, Handle<()>)
where
    E: Env + CryptoRng,
    C: Chain,
{
    start_inner(context, chain, operator, strategy, None)
}

#[cfg(test)]
pub(super) fn start_with_hooks<E, C>(
    context: E,
    chain: C,
    operator: Arc<Mutex<Operator>>,
    strategy: commonware_parallel::Rayon,
    hooks: TestHooks,
) -> (PaymentSender, Handle<()>)
where
    E: Env + CryptoRng,
    C: Chain,
{
    start_inner(context, chain, operator, strategy, Some(hooks))
}

fn start_inner<E, C>(
    context: E,
    chain: C,
    operator: Arc<Mutex<Operator>>,
    strategy: commonware_parallel::Rayon,
    #[cfg(test)] hooks: Option<TestHooks>,
    #[cfg(not(test))] _hooks: Option<()>,
) -> (PaymentSender, Handle<()>)
where
    E: Env + CryptoRng,
    C: Chain,
{
    let (sender, receiver) = mpsc::channel(MAX_PENDING_BATCHES);
    let handle = context.spawn(move |context| {
        run(
            context,
            chain,
            operator,
            strategy,
            receiver,
            #[cfg(test)]
            hooks,
        )
    });
    (PaymentSender(sender), handle)
}

pub(super) async fn submit(
    sender: &PaymentSender,
    request: operator_rpc::AcceptSendsRequest,
    kind: ResponseKind,
) -> rpc::Response {
    let (response, receiver) = oneshot::channel();
    if sender
        .0
        .send(Payment {
            request,
            kind,
            response,
        })
        .await
        .is_err()
    {
        return rpc::error_response("payment coordinator stopped".into());
    }
    receiver
        .await
        .unwrap_or_else(|_| rpc::error_response("payment coordinator stopped".into()))
}

#[cfg(test)]
pub(super) async fn enqueue(
    sender: &PaymentSender,
    request: operator_rpc::AcceptSendsRequest,
    kind: ResponseKind,
) -> oneshot::Receiver<rpc::Response> {
    let (response, receiver) = oneshot::channel();
    sender
        .0
        .send(Payment {
            request,
            kind,
            response,
        })
        .await
        .expect("payment coordinator is running");
    receiver
}

async fn run<E, C>(
    context: E,
    mut chain: C,
    operator: Arc<Mutex<Operator>>,
    strategy: commonware_parallel::Rayon,
    mut receiver: mpsc::Receiver<Payment>,
    #[cfg(test)] hooks: Option<TestHooks>,
) where
    E: Env + CryptoRng,
    C: Chain,
{
    let mut pending = VecDeque::new();
    let mut ready = None;
    loop {
        let group = match ready.take() {
            Some(group) => group,
            None => {
                let Some(payments) = next_group(&mut receiver, &mut pending).await else {
                    return;
                };
                verified(
                    spawn_verifier(
                        &context,
                        payments,
                        strategy.clone(),
                        #[cfg(test)]
                        hooks.clone(),
                    )
                    .await,
                )
            }
        };

        let mut group = group;
        if let Err(error) = operator.lock().ensure_store_usable() {
            let error = format!("{error:#}");
            reject_group(group, error.clone());
            panic!("payment storage failed: {error}");
        }
        preflight_group(&operator, &mut group);
        if let Err(error) = operator.lock().ensure_store_usable() {
            let error = format!("{error:#}");
            reject_group(group, error.clone());
            panic!("payment storage failed: {error}");
        }
        if let Err(error) = register_epoch(&context, &mut chain, &operator, |operator| {
            let mut required = false;
            let mut first_error = None;
            for verified in group
                .verified
                .iter()
                .filter_map(|result| result.as_ref().ok())
            {
                match operator.send_requires_epoch_registration_verified(verified) {
                    Ok(candidate) => required |= candidate,
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                }
            }
            if required {
                Ok(true)
            } else if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(false)
            }
        })
        .await
        {
            let error = format!("{error:#}");
            let fatal = operator
                .lock()
                .ensure_store_usable()
                .err()
                .map(|fault| format!("{fault:#}"));
            reject_group(group, error);
            if let Some(fatal) = fatal {
                panic!("payment storage failed: {fatal}");
            }
            continue;
        }
        if let Err(error) = operator.lock().ensure_store_usable() {
            let error = format!("{error:#}");
            reject_group(group, error.clone());
            panic!("payment storage failed: {error}");
        }

        let mut writer = context.child("writer").shared(true).spawn({
            let operator = operator.clone();
            move |_| async move { write_group(&operator, group) }
        });

        let ahead = if !pending.is_empty() {
            let payments = take_group(&mut pending);
            Some(spawn_verifier(
                &context,
                payments,
                strategy.clone(),
                #[cfg(test)]
                hooks.clone(),
            ))
        } else {
            select! {
                result = &mut writer => {
                    let completed = result.expect("payment writer task failed");
                    let fatal = completed.fatal.clone();
                    finish_group(completed);
                    if let Some(error) = fatal {
                        panic!("payment storage failed: {error}");
                    }
                    continue;
                },
                payment = receiver.recv() => {
                    payment.map(|payment| {
                        pending.push_back(payment);
                        while let Ok(payment) = receiver.try_recv() {
                            pending.push_back(payment);
                        }
                        let payments = take_group(&mut pending);
                        spawn_verifier(
                            &context,
                            payments,
                            strategy.clone(),
                            #[cfg(test)]
                            hooks.clone(),
                        )
                    })
                },
            }
        };

        let completed = writer.await.expect("payment writer task failed");
        let fatal = completed.fatal.clone();
        finish_group(completed);
        if fatal.is_some() {
            receiver.close();
        }
        let ahead = match ahead {
            Some(ahead) => Some(verified(ahead.await)),
            None => None,
        };
        if let Some(error) = fatal {
            if let Some(group) = ahead {
                reject_group(group, error.clone());
            }
            panic!("payment storage failed: {error}");
        }
        ready = ahead;
    }
}

fn preflight_group(operator: &Mutex<Operator>, group: &mut VerifiedGroup) {
    let operator = operator.lock();
    for result in &mut group.verified {
        let error = result.as_ref().map_or_else(
            |_| None,
            |verified| {
                operator
                    .send_requires_epoch_registration_verified(verified)
                    .err()
            },
        );
        if let Some(error) = error {
            *result = Err(error);
        }
    }
}

fn spawn_verifier<E: Spawner + CryptoRng>(
    context: &E,
    payments: Vec<Payment>,
    strategy: commonware_parallel::Rayon,
    #[cfg(test)] hooks: Option<TestHooks>,
) -> Handle<VerifiedGroup> {
    let requests = payments
        .iter()
        .map(|payment| payment.request.clone())
        .collect();
    context
        .child("verifier")
        .shared(true)
        .spawn(move |mut context| async move {
            #[cfg(test)]
            if let Some(hooks) = &hooks {
                let _ = hooks.verifier_started.send(());
            }
            let verified = verify_sends(requests, &mut context, &strategy);
            #[cfg(test)]
            if let Some(hooks) = &hooks {
                let _ = hooks.verifier_finished.send(());
            }
            assert_eq!(
                verified.len(),
                payments.len(),
                "payment verifier changed group cardinality"
            );
            VerifiedGroup { payments, verified }
        })
}

fn verified(result: Result<VerifiedGroup, commonware_runtime::Error>) -> VerifiedGroup {
    result.expect("payment verifier task failed")
}

async fn next_group(
    receiver: &mut mpsc::Receiver<Payment>,
    pending: &mut VecDeque<Payment>,
) -> Option<Vec<Payment>> {
    if pending.is_empty() {
        pending.push_back(receiver.recv().await?);
    }
    while let Ok(payment) = receiver.try_recv() {
        pending.push_back(payment);
    }
    Some(take_group(pending))
}

fn take_group(pending: &mut VecDeque<Payment>) -> Vec<Payment> {
    let available = pending.len();
    let mut payers = BTreeSet::<Key>::new();
    let mut group = Vec::with_capacity(MAX_VERIFICATION_BATCHES.min(available));
    for _ in 0..available {
        let payment = pending.pop_front().expect("pending length was captured");
        let payer = payment
            .request
            .sends
            .first()
            .map(|send| send.authorization.body().payer().clone());
        let unique = payer.is_none_or(|payer| payers.insert(payer));
        if unique && group.len() < MAX_VERIFICATION_BATCHES {
            group.push(payment);
        } else {
            pending.push_back(payment);
        }
    }
    group
}

fn write_group(operator: &Mutex<Operator>, group: VerifiedGroup) -> CompletedGroup {
    let mut fresh = Vec::new();
    let mut positions = Vec::new();
    let mut responses = Vec::new();
    for (index, (payment, verified)) in group.payments.into_iter().zip(group.verified).enumerate() {
        match verified {
            Ok(verified) => {
                positions.push((index, payment));
                fresh.push(verified);
            }
            Err(error) => {
                responses.push((index, payment, rpc::error_response(format!("{error:#}"))))
            }
        }
    }
    if fresh.is_empty() {
        return CompletedGroup {
            responses,
            fatal: None,
        };
    }
    let result = operator.lock().accept_verified_sends(fresh);
    match result {
        Ok(outcomes) => {
            assert_eq!(
                outcomes.len(),
                positions.len(),
                "payment writer changed group cardinality"
            );
            responses.extend(positions.into_iter().zip(outcomes).map(
                |((index, payment), outcome)| {
                    let response = match outcome {
                        Ok(outcome) => encode_outcome(payment.kind, outcome)
                            .unwrap_or_else(|error| rpc::error_response(format!("{error:#}"))),
                        Err(error) => rpc::error_response(format!("{error:#}")),
                    };
                    (index, payment, response)
                },
            ));
            responses.sort_unstable_by_key(|(index, _, _)| *index);
            CompletedGroup {
                responses,
                fatal: None,
            }
        }
        Err(error) => {
            let error = format!("{error:#}");
            let fatal = operator
                .lock()
                .ensure_store_usable()
                .err()
                .map(|error| format!("{error:#}"));
            responses.extend(
                positions
                    .into_iter()
                    .map(|(index, payment)| (index, payment, rpc::error_response(error.clone()))),
            );
            responses.sort_unstable_by_key(|(index, _, _)| *index);
            CompletedGroup { responses, fatal }
        }
    }
}

fn encode_outcome(kind: ResponseKind, outcome: SendsOutcome) -> Result<rpc::Response> {
    let body = match kind {
        ResponseKind::Batch => operator_rpc::AcceptSendsResponse::from(outcome).encode(),
        ResponseKind::Single => {
            let response = match outcome {
                SendsOutcome::Accepted(mut accepted) => {
                    ensure!(
                        accepted.len() == 1,
                        "single send returned multiple acceptances"
                    );
                    operator_rpc::AcceptSendResponse::Accepted(accepted.remove(0).into())
                }
                SendsOutcome::Stale {
                    context,
                    cumulative_debit,
                    seq,
                    entries,
                } => operator_rpc::AcceptSendResponse::Stale {
                    context,
                    cumulative_debit,
                    seq,
                    entries,
                },
            };
            response.encode()
        }
    };
    Ok(rpc::Response::Success { body })
}

fn reject_group(group: VerifiedGroup, error: String) {
    for (payment, verified) in group.payments.into_iter().zip(group.verified) {
        let response = match verified {
            Ok(_) => rpc::error_response(error.clone()),
            Err(error) => rpc::error_response(format!("{error:#}")),
        };
        let _ = payment.response.send(response);
    }
}

fn finish_group(group: CompletedGroup) {
    for (_, payment, response) in group.responses {
        let _ = payment.response.send(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wallets;
    use bytes::Bytes;
    use commonware_macros::select;
    use commonware_runtime::{
        Error as RuntimeError, Runner as _, Supervisor as _, deterministic, mocks,
    };
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use std::{net::SocketAddr, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};

    struct QueuedListener {
        connections: Vec<(SocketAddr, mocks::Sink, mocks::Stream)>,
    }

    impl Listener for QueuedListener {
        type Sink = mocks::Sink;
        type Stream = mocks::Stream;

        async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), RuntimeError> {
            match self.connections.pop() {
                Some(connection) => Ok(connection),
                None => std::future::pending().await,
            }
        }

        fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 1)))
        }
    }

    fn verified_payment_group() -> (
        Mutex<Operator>,
        VerifiedGroup,
        oneshot::Receiver<rpc::Response>,
    ) {
        let operator = Mutex::new(
            Operator::open(Path::new(":memory:"), NonZeroUsize::new(2).unwrap()).unwrap(),
        );
        let recipient = wallets()[1].public_key();
        let request = {
            let operator = operator.lock();
            let (authorization, entries) = operator.sign_send(0, &[(recipient, 1)]).unwrap();
            operator_rpc::AcceptSendsRequest {
                sends: vec![operator_rpc::AcceptSendRequest {
                    authorization,
                    entries,
                }],
            }
        };
        let strategy = operator.lock().payment_strategy();
        let verified = verify_sends(
            vec![request.clone()],
            &mut commonware_utils::test_rng(),
            &strategy,
        )
        .pop()
        .unwrap();
        let (response, receiver) = oneshot::channel();
        let group = VerifiedGroup {
            payments: vec![Payment {
                request,
                kind: ResponseKind::Batch,
                response,
            }],
            verified: vec![verified],
        };
        (operator, group, receiver)
    }

    #[test]
    fn second_connection_completes_while_first_handler_is_blocked() {
        deterministic::Runner::default().start(|context| async move {
            let (mut first_request, first_stream) = mocks::Channel::init();
            let (first_sink, mut first_response) = mocks::Channel::init();
            let (mut second_request, second_stream) = mocks::Channel::init();
            let (second_sink, mut second_response) = mocks::Channel::init();
            let listener = QueuedListener {
                connections: vec![
                    (
                        SocketAddr::from(([127, 0, 0, 1], 3)),
                        second_sink,
                        second_stream,
                    ),
                    (
                        SocketAddr::from(([127, 0, 0, 1], 2)),
                        first_sink,
                        first_stream,
                    ),
                ],
            };
            let (entered, first_entered) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let entered = Arc::new(Mutex::new(Some(entered)));
            let released = Arc::new(Mutex::new(Some(released)));
            let server = context.child("server").spawn({
                let entered = entered.clone();
                let released = released.clone();
                move |context| {
                    serve_connections(context, listener, move |request| {
                        let entered = entered.clone();
                        let released = released.clone();
                        async move {
                            if request.method == 1 {
                                entered.lock().take().unwrap().send(()).unwrap();
                                let released = released.lock().take().unwrap();
                                released.await.unwrap();
                            }
                            rpc::Response::Success { body: request.body }
                        }
                    })
                }
            });

            rpc::send_request(
                &mut first_request,
                &rpc::Request {
                    method: 1,
                    body: Bytes::from_static(b"first"),
                },
            )
            .await
            .unwrap();
            first_entered.await.unwrap();
            rpc::send_request(
                &mut second_request,
                &rpc::Request {
                    method: 2,
                    body: Bytes::from_static(b"second"),
                },
            )
            .await
            .unwrap();

            let progressed = select! {
                response = rpc::recv_response(&mut second_response) => {
                    assert_eq!(
                        response.unwrap(),
                        rpc::Response::Success {
                            body: Bytes::from_static(b"second"),
                        }
                    );
                    true
                },
                _ = context.sleep(Duration::from_secs(1)) => false,
            };

            release.send(()).unwrap();
            assert_eq!(
                rpc::recv_response(&mut first_response).await.unwrap(),
                rpc::Response::Success {
                    body: Bytes::from_static(b"first"),
                }
            );
            server.abort();
            let _ = server.await;
            assert!(
                progressed,
                "the second connection was blocked behind the first"
            );
        });
    }

    #[test]
    fn semantic_fence_rejects_group_without_fatal_storage_shutdown() {
        deterministic::Runner::default().start(|_context| async move {
            let (operator, group, receiver) = verified_payment_group();
            operator
                .lock()
                .fence_suffix(0, "certified test fence".into())
                .unwrap();

            let completed = write_group(&operator, group);
            let fatal = completed.fatal.clone();
            finish_group(completed);
            let response = receiver.await.unwrap();

            assert!(
                fatal.is_none(),
                "a semantic fence was classified as storage-fatal"
            );
            assert!(operator.lock().ensure_store_usable().is_ok());
            assert!(matches!(response, rpc::Response::Error { .. }));
        });
    }

    #[test]
    fn storage_commit_failure_fatally_stops_group() {
        deterministic::Runner::default().start(|_context| async move {
            let (operator, group, receiver) = verified_payment_group();
            operator.lock().fail_next_payment_commit();

            let completed = write_group(&operator, group);
            let fatal = completed.fatal.clone();
            finish_group(completed);
            let response = receiver.await.unwrap();

            assert!(fatal.is_some(), "a storage failure was treated as semantic");
            assert!(operator.lock().ensure_store_usable().is_err());
            assert!(matches!(response, rpc::Response::Error { .. }));
        });
    }
}
