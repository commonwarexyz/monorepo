//! Mailbox and wire types for the QMDB sync resolver service.

use crate::stateful::db::{AttachableResolver, Shared, p2p::cancel};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Request, Response, Source, Verifier},
};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, future::Future};

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Verifier and result channel for a pending request.
pub(super) struct Reply<R, V>
where
    V: Verifier<R>,
{
    verify: V,
    response: Option<oneshot::Sender<V::Output>>,
}

impl<R, V> Reply<R, V>
where
    V: Verifier<R>,
{
    pub(super) const fn new(verify: V, response: oneshot::Sender<V::Output>) -> Self {
        Self {
            verify,
            response: Some(response),
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        self.response
            .as_ref()
            .is_none_or(oneshot::Sender::is_closed)
    }

    /// Return whether the response is valid, or `None` if the caller stopped waiting.
    pub(super) fn deliver(&mut self, response: R) -> Option<bool> {
        if self.is_closed() {
            return None;
        }
        let Some(verified) = self.verify.verify(response) else {
            return Some(false);
        };
        self.response
            .take()
            .expect("live response channel")
            .send(verified)
            .ok()
            .map(|()| true)
    }
}

/// Messages sent from the [`Mailbox`] to the resolver [`Actor`](super::Actor).
pub(super) enum Message<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    /// Provide a database handle so the actor can serve incoming requests.
    AttachDatabase(Shared<DB>),
    /// Fetch operations from a remote peer via the P2P resolver engine.
    GetOperations {
        request: Request<F>,
        response: Reply<Response<F, Op, D>, V>,
    },
    /// Cancel subscriptions for this request whose response channels have closed.
    CancelOperations { request: Request<F> },
}

impl<DB, F, Op, D, V> Message<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachDatabase(_) | Self::CancelOperations { .. } => false,
            Self::GetOperations { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    database: Option<Shared<DB>>,
    messages: VecDeque<Message<DB, F, Op, D, V>>,
}

impl<DB, F, Op, D, V> Default for Pending<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    fn default() -> Self {
        Self {
            database: None,
            messages: VecDeque::new(),
        }
    }
}

impl<DB, F, Op, D, V> Overflow<Message<DB, F, Op, D, V>> for Pending<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    fn is_empty(&self) -> bool {
        self.database.is_none() && self.messages.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<DB, F, Op, D, V>) -> Option<Message<DB, F, Op, D, V>>,
    {
        if let Some(database) = self.database.take()
            && let Some(Message::AttachDatabase(database)) = push(Message::AttachDatabase(database))
        {
            self.database = Some(database);
            return;
        }

        while let Some(message) = self.messages.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<DB, F, Op, D, V> Policy for Message<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    type Overflow = Pending<DB, F, Op, D, V>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        match message {
            Self::AttachDatabase(database) => {
                overflow.database = Some(database);
            }
            message => overflow.messages.push_back(message),
        }
    }
}

/// Resolver mailbox for a single QMDB history.
pub struct Mailbox<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    sender: Sender<Message<DB, F, Op, D, V>>,
}

impl<DB, F, Op, D, V> Clone for Mailbox<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<DB, F, Op, D, V> Mailbox<DB, F, Op, D, V>
where
    F: Family,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    pub(super) const fn new(sender: Sender<Message<DB, F, Op, D, V>>) -> Self {
        Self { sender }
    }
}

impl<DB, F, Op, D, V> Mailbox<DB, F, Op, D, V>
where
    DB: Send + Sync,
    F: Family,
    Op: Send,
    D: Digest,
    V: Verifier<Response<F, Op, D>>,
{
    pub fn attach_database(&self, db: Shared<DB>) {
        let _ = self.sender.enqueue(Message::AttachDatabase(db));
    }
}

impl<DB, F, Op, D, V> Source<V> for Mailbox<DB, F, Op, D, V>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: Send + Sync + 'static,
    V: Verifier<Response<F, Op, D>>,
{
    type Family = F;
    type Digest = D;
    type Op = Op;
    type Error = ResponseDropped;

    async fn serve(
        &self,
        request: Request<F>,
        verify: V,
    ) -> Result<Option<V::Output>, Self::Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetOperations {
            request,
            response: Reply::new(verify, response_tx),
        });

        let mut guard =
            cancel::Guard::new(self.sender.clone(), Message::CancelOperations { request });
        let result = response_rx.await;
        guard.disarm();
        result.map(Some).map_err(|_| ResponseDropped)
    }
}

impl<DB, F, Op, D, V> AttachableResolver<DB> for Mailbox<DB, F, Op, D, V>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: Send + Sync + 'static,
    V: Verifier<Response<F, Op, D>> + 'static,
    V::Output: 'static,
{
    fn attach_database(&self, db: Shared<DB>) -> impl Future<Output = ()> + Send {
        Self::attach_database(self, db);
        std::future::ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::{mmr, qmdb::sync::Identity};
    use commonware_utils::{NZU64, NZUsize};

    #[test]
    fn overflow_keeps_latest_database_and_orders_live_requests() {
        deterministic::Runner::default().start(|_| async move {
            let mut overflow =
                Pending::<u64, mmr::Family, u64, sha256::Digest, Identity>::default();
            let request = Request::Operations {
                size: mmr::Location::new(10),
                start: mmr::Location::new(3),
                max_ops: NZU64!(2),
            };
            Message::handle(
                &mut overflow,
                Message::AttachDatabase(Shared::new("overflow_old", 1)),
            );

            // A canceled caller can leave both its request and cancellation in overflow.
            let (response, canceled) = oneshot::channel();
            Message::handle(
                &mut overflow,
                Message::GetOperations {
                    request,
                    response: Reply::new(Identity, response),
                },
            );
            drop(canceled);
            Message::handle(&mut overflow, Message::CancelOperations { request });

            // A later caller for the same request must remain behind the cancellation.
            let (response, _waiting) = oneshot::channel();
            Message::handle(
                &mut overflow,
                Message::GetOperations {
                    request,
                    response: Reply::new(Identity, response),
                },
            );
            Message::handle(
                &mut overflow,
                Message::AttachDatabase(Shared::new("overflow_new", 2)),
            );

            // A full ready queue must preserve both the attachment and the first queued message.
            overflow.drain(Some);
            let mut messages = VecDeque::new();
            overflow.drain(|message| {
                if matches!(&message, Message::AttachDatabase(_)) {
                    messages.push_back(message);
                    None
                } else {
                    Some(message)
                }
            });

            overflow.drain(|message| {
                messages.push_back(message);
                None
            });
            assert!(overflow.is_empty());

            let Some(Message::AttachDatabase(database)) = messages.pop_front() else {
                panic!("expected the latest database before queued requests");
            };
            assert_eq!(*database.read().await, 2);
            assert!(matches!(
                messages.pop_front(),
                Some(Message::CancelOperations { request: canceled }) if canceled == request
            ));
            assert!(matches!(
                messages.pop_front(),
                Some(Message::GetOperations { request: queued, response })
                    if queued == request && !response.is_closed()
            ));
            assert!(messages.is_empty());
        });
    }

    /// A caller that abandons its fetch drops the future, which retracts the request from the
    /// actor.
    #[test]
    fn dropping_get_operations_sends_cancel_message() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<(), mmr::Family, u64, sha256::Digest, Identity>::new(sender);
            let size = mmr::Location::new(10);
            let start_loc = mmr::Location::new(3);
            let max_ops = NZU64!(2);

            // Poll once so the request is enqueued, then abandon the fetch.
            {
                let get = mailbox.serve(
                    Request::Operations {
                        size,
                        start: start_loc,
                        max_ops,
                    },
                    Identity,
                );
                futures::pin_mut!(get);
                assert!(futures::poll!(get.as_mut()).is_pending());
            }

            match receiver.recv().await.expect("request should be queued") {
                Message::GetOperations { request, .. } => {
                    assert_eq!(request.size(), size);
                    assert_eq!(request.start(), start_loc);
                    assert_eq!(request.max_ops(), max_ops);
                    assert!(matches!(request, Request::Operations { .. }));
                }
                Message::AttachDatabase(_) => panic!("unexpected attach message"),
                Message::CancelOperations { .. } => panic!("cancel should come after request"),
            }

            match receiver.recv().await.expect("cancel should be queued") {
                Message::CancelOperations { request } => {
                    assert_eq!(request.size(), size);
                    assert_eq!(request.start(), start_loc);
                    assert_eq!(request.max_ops(), max_ops);
                    assert!(matches!(request, Request::Operations { .. }));
                }
                Message::AttachDatabase(_) => panic!("unexpected attach message"),
                Message::GetOperations { .. } => panic!("unexpected duplicate request"),
            }
        });
    }

    /// A closed response ends the fetch and disarms its cancellation guard.
    #[test]
    fn completed_get_operations_sends_no_cancel() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<(), mmr::Family, u64, sha256::Digest, Identity>::new(sender);
            let get = mailbox.serve(
                Request::Operations {
                    size: mmr::Location::new(10),
                    start: mmr::Location::new(3),
                    max_ops: NZU64!(2),
                },
                Identity,
            );
            let observe = async move {
                let Message::GetOperations { response, .. } =
                    receiver.recv().await.expect("request should be queued")
                else {
                    panic!("expected a fetch request");
                };
                drop(response);
                receiver
            };

            let (result, mut receiver) = futures::join!(get, observe);
            assert!(matches!(result, Err(ResponseDropped)));
            assert!(
                receiver.try_recv().is_err(),
                "a completed fetch must not enqueue a cancel"
            );
        });
    }

    #[test]
    fn rejected_candidate_keeps_request_until_acceptance_or_cancellation() {
        deterministic::Runner::default().start(|context| async move {
            for cancel in [false, true] {
                let (sender, mut receiver) = commonware_actor::mailbox::new(
                    context.child(if cancel { "cancel" } else { "accept" }),
                    NZUsize!(4),
                );
                let mailbox = Mailbox::<(), mmr::Family, u64, sha256::Digest, _>::new(sender);
                let request = Request::Operations {
                    size: mmr::Location::new(1),
                    start: mmr::Location::new(0),
                    max_ops: NZU64!(1),
                };
                let mut fetch = Box::pin(mailbox.serve(
                    request,
                    |candidate: Response<mmr::Family, u64, sha256::Digest>| match candidate {
                        Response::Operations { operations, .. } => {
                            operations.first().copied().filter(|value| *value == 2)
                        }
                        Response::Boundary { .. } => None,
                    },
                ));
                assert!(futures::poll!(fetch.as_mut()).is_pending());
                let Message::GetOperations { mut response, .. } = receiver.recv().await.unwrap()
                else {
                    panic!("expected a fetch request");
                };
                let candidate = |value| Response::Operations {
                    proof: mmr::Proof {
                        leaves: request.size(),
                        inactive_peaks: 0,
                        digests: vec![],
                    },
                    operations: vec![value],
                };

                assert_eq!(response.deliver(candidate(1)), Some(false));
                assert!(futures::poll!(fetch.as_mut()).is_pending());
                assert!(receiver.try_recv().is_err());

                if cancel {
                    drop(fetch);
                    assert!(matches!(
                        receiver.recv().await.unwrap(),
                        Message::CancelOperations { request: canceled } if canceled == request
                    ));
                } else {
                    assert_eq!(response.deliver(candidate(2)), Some(true));
                    assert_eq!(fetch.await.unwrap(), Some(2));
                    assert!(receiver.try_recv().is_err());
                }
                assert!(response.is_closed());
            }
        });
    }
}
