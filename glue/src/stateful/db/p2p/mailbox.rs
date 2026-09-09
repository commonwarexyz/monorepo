//! Mailbox and wire types for the QMDB sync resolver service.

use crate::stateful::db::p2p::cancel;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{FeedbackTx, Request, Response, Source},
};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Where the actor delivers a fetched response, along with the channel the caller reports
/// verification feedback on.
pub(super) type ResponseTx<F, Op, D> = oneshot::Sender<(Response<F, Op, D>, FeedbackTx)>;

/// Messages sent from the [`Mailbox`] to the resolver [`Actor`](super::Actor).
pub(super) enum Message<F: Family, Op, D: Digest> {
    /// Fetch operations from a remote peer via the P2P resolver engine.
    GetOperations {
        request: Request<F>,
        response: ResponseTx<F, Op, D>,
    },
    /// Cancel a previously requested operation fetch.
    CancelOperations { request: Request<F> },
}

impl<F: Family, Op, D: Digest> Message<F, Op, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::CancelOperations { .. } => false,
            Self::GetOperations { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<F: Family, Op, D: Digest>(VecDeque<Message<F, Op, D>>);

impl<F: Family, Op, D: Digest> Default for Pending<F, Op, D> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<F: Family, Op, D: Digest> Overflow<Message<F, Op, D>> for Pending<F, Op, D> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<F, Op, D>) -> Option<Message<F, Op, D>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl<F: Family, Op, D: Digest> Policy for Message<F, Op, D> {
    type Overflow = Pending<F, Op, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

/// Client-facing resolver mailbox used by the QMDB sync engine.
pub struct Mailbox<F: Family, Op, D: Digest> {
    sender: Sender<Message<F, Op, D>>,
}

impl<F: Family, Op, D: Digest> Clone for Mailbox<F, Op, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<F: Family, Op, D: Digest> Mailbox<F, Op, D> {
    pub(super) const fn new(sender: Sender<Message<F, Op, D>>) -> Self {
        Self { sender }
    }
}

impl<F, Op, D> Source for Mailbox<F, Op, D>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
{
    type Family = F;
    type Digest = D;
    type Op = Op;
    type Error = ResponseDropped;

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        let (response_tx, response_rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetOperations {
            request,
            response: response_tx,
        });

        let mut guard =
            cancel::Guard::new(self.sender.clone(), Message::CancelOperations { request });
        let result = response_rx.await;
        guard.disarm();
        result.map_err(|_| ResponseDropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_storage::mmr;
    use commonware_utils::{NZU64, NZUsize};

    /// A caller that abandons its fetch drops the future, which retracts the request from the
    /// actor.
    #[test]
    fn dropping_get_operations_sends_cancel_message() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<mmr::Family, u64, sha256::Digest>::new(sender);
            let size = mmr::Location::new(10);
            let start_loc = mmr::Location::new(3);
            let max_ops = NZU64!(2);

            // Poll once so the request is enqueued, then abandon the fetch.
            {
                let get = mailbox.serve(Request::Operations {
                    size,
                    start: start_loc,
                    max_ops,
                });
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
                Message::CancelOperations { .. } => panic!("cancel should come after request"),
            }

            match receiver.recv().await.expect("cancel should be queued") {
                Message::CancelOperations { request } => {
                    assert_eq!(request.size(), size);
                    assert_eq!(request.start(), start_loc);
                    assert_eq!(request.max_ops(), max_ops);
                    assert!(matches!(request, Request::Operations { .. }));
                }
                Message::GetOperations { .. } => panic!("unexpected duplicate request"),
            }
        });
    }

    /// A fetch that completes normally disarms the guard, so no cancel follows.
    #[test]
    fn completed_get_operations_sends_no_cancel() {
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
}
