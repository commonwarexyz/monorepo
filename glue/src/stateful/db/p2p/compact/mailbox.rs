//! Mailbox for the compact QMDB P2P resolver.

use super::handler;
use crate::stateful::db::AttachableResolver;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{merkle::Family, qmdb::sync::compact};
use commonware_utils::{channel::oneshot, sync::TracedAsyncRwLock};
use std::{collections::VecDeque, sync::Arc};

struct CancelGuard<R, F: Family, Op, D: Digest> {
    sender: Sender<Message<R, F, Op, D>>,
    request: Option<handler::Request<F, D>>,
}

impl<R, F: Family, Op, D: Digest> CancelGuard<R, F, Op, D> {
    const fn new(sender: Sender<Message<R, F, Op, D>>, request: handler::Request<F, D>) -> Self {
        Self {
            sender,
            request: Some(request),
        }
    }

    const fn disarm(&mut self) {
        self.request = None;
    }
}

impl<R, F: Family, Op, D: Digest> Drop for CancelGuard<R, F, Op, D> {
    fn drop(&mut self) {
        let Some(request) = self.request.take() else {
            return;
        };
        let _ = self.sender.enqueue(Message::CancelState { request });
    }
}

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

pub(super) enum Message<R, F: Family, Op, D: Digest> {
    AttachDatabase(R),
    GetState {
        request: handler::Request<F, D>,
        response: oneshot::Sender<Result<compact::FetchResult<F, Op, D>, ResponseDropped>>,
    },
    CancelState {
        request: handler::Request<F, D>,
    },
}

impl<R, F: Family, Op, D: Digest> Message<R, F, Op, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachDatabase(_) | Self::CancelState { .. } => false,
            Self::GetState { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<R, F: Family, Op, D: Digest> {
    database: Option<R>,
    messages: VecDeque<Message<R, F, Op, D>>,
}

impl<R, F: Family, Op, D: Digest> Default for Pending<R, F, Op, D> {
    fn default() -> Self {
        Self {
            database: None,
            messages: VecDeque::new(),
        }
    }
}

impl<R, F: Family, Op, D: Digest> Overflow<Message<R, F, Op, D>> for Pending<R, F, Op, D> {
    fn is_empty(&self) -> bool {
        self.database.is_none() && self.messages.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<R, F, Op, D>) -> Option<Message<R, F, Op, D>>,
    {
        if let Some(database) = self.database.take() {
            if let Some(Message::AttachDatabase(database)) = push(Message::AttachDatabase(database))
            {
                self.database = Some(database);
                return;
            }
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

impl<R, F: Family, Op, D: Digest> Policy for Message<R, F, Op, D> {
    type Overflow = Pending<R, F, Op, D>;

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

/// Client-facing resolver mailbox used by compact QMDB sync.
pub struct Mailbox<R, F: Family, Op, H: Hasher> {
    sender: Sender<Message<R, F, Op, H::Digest>>,
}

impl<R, F: Family, Op, H: Hasher> Clone for Mailbox<R, F, Op, H> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<R, F: Family, Op, H: Hasher> Mailbox<R, F, Op, H> {
    pub(super) const fn new(sender: Sender<Message<R, F, Op, H::Digest>>) -> Self {
        Self { sender }
    }
}

impl<R: Send + Sync, F: Family, Op: Send, H: Hasher> Mailbox<R, F, Op, H> {
    pub fn attach_database(&self, resolver: R) {
        let _ = self.sender.enqueue(Message::AttachDatabase(resolver));
    }
}

impl<R, F, Op, H> compact::Resolver for Mailbox<R, F, Op, H>
where
    R: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    type Digest = H::Digest;
    type Error = ResponseDropped;
    type Family = F;
    type Op = Op;

    async fn get_compact_state(
        &self,
        target: compact::Target<Self::Family, Self::Digest>,
    ) -> Result<compact::FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let request = handler::Request::from_target(target);
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetState {
            request: request.clone(),
            response,
        });
        let mut cancel = CancelGuard::new(self.sender.clone(), request);
        let result = receiver.await;
        cancel.disarm();
        result.map_err(|_| ResponseDropped)?
    }
}

impl<DB, F, Op, H> AttachableResolver<DB> for Mailbox<DB::Resolver, F, Op, H>
where
    DB: compact::Provider + Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
    DB::Resolver: compact::Resolver<Family = F, Digest = H::Digest, Op = Op>,
{
    async fn attach_database(&self, db: Arc<TracedAsyncRwLock<DB>>) {
        let resolver = compact::Provider::resolver(&*db.read().await);
        Self::attach_database(self, resolver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_storage::{mmr, qmdb::sync::compact::Resolver as _};
    use commonware_utils::NZUsize;
    use futures::{future::poll_fn, Future};
    use std::task::Poll;

    #[test]
    fn get_compact_state_sends_request() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<(), mmr::Family, u64, Sha256>::new(sender);
            let target = compact::Target {
                root: [1u8; 32].into(),
                leaf_count: mmr::Location::new(7),
            };

            let get = mailbox.get_compact_state(target.clone());
            let observe = async move {
                let message = receiver.recv().await.expect("request should be queued");
                let Message::GetState { request, response } = message else {
                    panic!("unexpected attach message");
                };
                assert_eq!(request.to_target(), target);
                drop(response);
            };

            let (result, _) = futures::join!(get, observe);
            assert!(matches!(result, Err(ResponseDropped)));
        });
    }

    #[test]
    fn dropped_request_sends_cancel_message() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<(), mmr::Family, u64, Sha256>::new(sender);
            let target = compact::Target {
                root: [2u8; 32].into(),
                leaf_count: mmr::Location::new(9),
            };

            let mut get = Box::pin(mailbox.get_compact_state(target.clone()));
            poll_fn(|cx| {
                assert!(matches!(get.as_mut().poll(cx), Poll::Pending));
                Poll::Ready(())
            })
            .await;
            drop(get);

            let message = receiver.recv().await.expect("request should be queued");
            let Message::GetState { request, response } = message else {
                panic!("unexpected attach message");
            };
            assert_eq!(request.to_target(), target);
            drop(response);

            match receiver.recv().await.expect("cancel should be queued") {
                Message::CancelState { request } => {
                    assert_eq!(request.to_target(), target);
                }
                Message::AttachDatabase(_) => panic!("unexpected attach message"),
                Message::GetState { .. } => panic!("unexpected duplicate request"),
            }
        });
    }
}
