//! Mailbox and wire types for the QMDB sync resolver service.

use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::Digest;
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Feedback, Request, Response, Source, source},
};
use commonware_utils::channel::{mpsc, oneshot};
use std::collections::VecDeque;

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Candidate responses and the channels through which callers judge them.
pub(super) type Reply<R> = mpsc::Sender<(R, oneshot::Sender<bool>)>;

/// Messages sent from the [`Mailbox`] to the resolver [`Actor`](super::Actor).
pub(super) enum Message<F, Op, D>
where
    F: Family,
    D: Digest,
{
    /// Fetch operations from a remote peer via the P2P resolver engine.
    GetOperations {
        request: Request<F>,
        response: Reply<Response<F, Op, D>>,
    },
}

impl<F, Op, D> Message<F, Op, D>
where
    F: Family,
    D: Digest,
{
    fn response_closed(&self) -> bool {
        match self {
            Self::GetOperations { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<F, Op, D>
where
    F: Family,
    D: Digest,
{
    messages: VecDeque<Message<F, Op, D>>,
}

impl<F, Op, D> Default for Pending<F, Op, D>
where
    F: Family,
    D: Digest,
{
    fn default() -> Self {
        Self {
            messages: VecDeque::new(),
        }
    }
}

impl<F, Op, D> Overflow<Message<F, Op, D>> for Pending<F, Op, D>
where
    F: Family,
    D: Digest,
{
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<F, Op, D>) -> Option<Message<F, Op, D>>,
    {
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

impl<F, Op, D> Policy for Message<F, Op, D>
where
    F: Family,
    D: Digest,
{
    type Overflow = Pending<F, Op, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        overflow.messages.push_back(message);
    }
}

/// Resolver mailbox for a single QMDB history.
pub struct Mailbox<F, Op, D>
where
    F: Family,
    D: Digest,
{
    sender: Sender<Message<F, Op, D>>,
}

impl<F, Op, D> Clone for Mailbox<F, Op, D>
where
    F: Family,
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<F, Op, D> Mailbox<F, Op, D>
where
    F: Family,
    D: Digest,
{
    pub(super) const fn new(sender: Sender<Message<F, Op, D>>) -> Self {
        Self { sender }
    }
}

impl<F, Op, D> Source for Mailbox<F, Op, D>
where
    F: Family,
    Op: Send,
    D: Digest,
{
    type Family = F;
    type Digest = D;
    type Op = Op;
    type Error = ResponseDropped;

    async fn serve(&self, request: Request<F>) -> source::Result<Self> {
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let _ = self.sender.enqueue(Message::GetOperations {
            request,
            response: response_tx,
        });

        let (response, verdict) = response_rx.recv().await.ok_or(ResponseDropped)?;
        Ok((response, Some(Feedback::new(verdict, response_rx))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::mmr;
    use commonware_utils::{NZU64, NZUsize};

    type TestResponse = Response<mmr::Family, u64, sha256::Digest>;

    #[test]
    fn overflow_orders_live_requests() {
        let mut overflow = Pending::<mmr::Family, u64, sha256::Digest>::default();
        let request = Request::Operations {
            size: mmr::Location::new(10),
            start: mmr::Location::new(3),
            max_ops: NZU64!(2),
        };
        let (response, canceled) = mpsc::channel(1);
        Message::handle(&mut overflow, Message::GetOperations { request, response });
        drop(canceled);
        let (response, _waiting) = mpsc::channel(1);
        Message::handle(&mut overflow, Message::GetOperations { request, response });
        overflow.drain(Some);
        let mut messages = VecDeque::new();
        overflow.drain(|message| {
            messages.push_back(message);
            None
        });
        assert!(overflow.is_empty());
        assert!(
            matches!(messages.pop_front(), Some(Message::GetOperations { request: queued, response }) if queued == request && !response.is_closed())
        );
        assert!(messages.is_empty());
    }

    #[test]
    fn dropping_get_operations_closes_queued_reply() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<mmr::Family, u64, sha256::Digest>::new(sender);
            let request = Request::Operations {
                size: mmr::Location::new(10),
                start: mmr::Location::new(3),
                max_ops: NZU64!(2),
            };

            // Poll once so the request is enqueued, then abandon the fetch.
            {
                let get = mailbox.serve(request);
                futures::pin_mut!(get);
                assert!(futures::poll!(get.as_mut()).is_pending());
            }

            let Message::GetOperations {
                request: queued,
                response,
            } = receiver.recv().await.expect("request should be queued");
            assert_eq!(queued, request);
            assert!(response.is_closed());
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn closed_response_ends_fetch() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<mmr::Family, u64, sha256::Digest>::new(sender);
            let get = mailbox.serve(Request::Operations {
                size: mmr::Location::new(10),
                start: mmr::Location::new(3),
                max_ops: NZU64!(2),
            });
            let observe = async move {
                let Message::GetOperations { response, .. } =
                    receiver.recv().await.expect("request should be queued");
                drop(response);
                receiver
            };

            let (result, mut receiver) = futures::join!(get, observe);
            assert!(matches!(result, Err(ResponseDropped)));
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn rejected_candidate_keeps_channel_until_acceptance_or_cancellation() {
        deterministic::Runner::default().start(|context| async move {
            for cancel in [false, true] {
                let (sender, mut receiver) = commonware_actor::mailbox::new(
                    context.child(if cancel { "cancel" } else { "accept" }),
                    NZUsize!(4),
                );
                let mailbox = Mailbox::<mmr::Family, u64, sha256::Digest>::new(sender);
                let request = Request::Operations {
                    size: mmr::Location::new(1),
                    start: mmr::Location::new(0),
                    max_ops: NZU64!(1),
                };
                let mut fetch = Box::pin(mailbox.serve(request));
                assert!(futures::poll!(fetch.as_mut()).is_pending());
                let Message::GetOperations { response, .. } = receiver.recv().await.unwrap();
                let candidate = |value| TestResponse::Operations {
                    proof: mmr::Proof {
                        leaves: request.size(),
                        inactive_peaks: 0,
                        digests: vec![],
                    },
                    operations: vec![value],
                };

                let (verdict, rejected) = oneshot::channel();
                assert!(response.try_send((candidate(1), verdict)).is_ok());
                let (first, feedback) = fetch.await.unwrap();
                assert!(matches!(first, Response::Operations { operations, .. } if operations == [1]));
                let mut retry = Box::pin(feedback.unwrap().reject());
                assert!(futures::poll!(retry.as_mut()).is_pending());
                assert!(!rejected.await.unwrap());
                assert!(!response.is_closed());
                assert!(receiver.try_recv().is_err());

                if cancel {
                    drop(retry);
                } else {
                    let (verdict, accepted) = oneshot::channel();
                    assert!(response.try_send((candidate(2), verdict)).is_ok());
                    let (second, feedback) = retry.await.unwrap();
                    assert!(matches!(second, Response::Operations { operations, .. } if operations == [2]));
                    feedback.accept();
                    assert!(accepted.await.unwrap());
                }
                response.closed().await;
                assert!(receiver.try_recv().is_err());
            }
        });
    }
}
