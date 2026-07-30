//! Mailbox for the compact QMDB P2P resolver.

use crate::stateful::db::{AttachableResolver, Shared, p2p::cancel::CancelGuard};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Response, Source, Validity, compact},
};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, future::Future};

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Where the actor delivers a fetched response, along with the channel the caller reports
/// peer validity on.
pub(super) type Delivery<F, Op, D> =
    oneshot::Sender<Result<(Response<F, Op, D>, Validity), ResponseDropped>>;

pub(super) enum Message<DB, F: Family, Op, D: Digest> {
    AttachDatabase(Shared<DB>),
    GetState {
        request: compact::Target<F, D>,
        response: Delivery<F, Op, D>,
    },
    CancelState {
        request: compact::Target<F, D>,
    },
}

impl<DB, F: Family, Op, D: Digest> Message<DB, F, Op, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachDatabase(_) | Self::CancelState { .. } => false,
            Self::GetState { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<DB, F: Family, Op, D: Digest> {
    database: Option<Shared<DB>>,
    messages: VecDeque<Message<DB, F, Op, D>>,
}

impl<DB, F: Family, Op, D: Digest> Default for Pending<DB, F, Op, D> {
    fn default() -> Self {
        Self {
            database: None,
            messages: VecDeque::new(),
        }
    }
}

impl<DB, F: Family, Op, D: Digest> Overflow<Message<DB, F, Op, D>> for Pending<DB, F, Op, D> {
    fn is_empty(&self) -> bool {
        self.database.is_none() && self.messages.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<DB, F, Op, D>) -> Option<Message<DB, F, Op, D>>,
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

impl<DB, F: Family, Op, D: Digest> Policy for Message<DB, F, Op, D> {
    type Overflow = Pending<DB, F, Op, D>;

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
pub struct Mailbox<DB, F: Family, Op, H: Hasher> {
    sender: Sender<Message<DB, F, Op, H::Digest>>,
}

impl<DB, F: Family, Op, H: Hasher> Clone for Mailbox<DB, F, Op, H> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<DB, F: Family, Op, H: Hasher> Mailbox<DB, F, Op, H> {
    pub(super) const fn new(sender: Sender<Message<DB, F, Op, H::Digest>>) -> Self {
        Self { sender }
    }
}

impl<DB: Send + Sync, F: Family, Op: Send, H: Hasher> Mailbox<DB, F, Op, H> {
    pub fn attach_database(&self, db: Shared<DB>) {
        let _ = self.sender.enqueue(Message::AttachDatabase(db));
    }
}

impl<DB, F, Op, H> Source<compact::Target<F, H::Digest>> for Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    type Digest = H::Digest;
    type Error = ResponseDropped;
    type Family = F;
    type Op = Op;

    async fn serve(
        &self,
        target: compact::Target<Self::Family, Self::Digest>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetState {
            request: target.clone(),
            response,
        });
        let mut cancel = CancelGuard::new(self.sender.clone(), Message::CancelState { request: target });
        let result = receiver.await;
        cancel.disarm();
        result.map_err(|_| ResponseDropped)?
    }
}

impl<DB, F, Op, H> AttachableResolver<DB> for Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    fn attach_database(&self, db: Shared<DB>) -> impl Future<Output = ()> + Send {
        Self::attach_database(self, db);
        std::future::ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_storage::mmr;
    use commonware_utils::NZUsize;
    use futures::future::poll_fn;
    use std::task::Poll;

    #[test]
    fn serve_sends_request() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
            let mailbox = Mailbox::<(), mmr::Family, u64, Sha256>::new(sender);
            let target = compact::Target {
                root: [1u8; 32].into(),
                leaf_count: mmr::Location::new(7),
            };

            let get = mailbox.serve(target.clone());
            let observe = async move {
                let message = receiver.recv().await.expect("request should be queued");
                let Message::GetState { request, response } = message else {
                    panic!("unexpected attach message");
                };
                assert_eq!(request, target);
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

            let mut get = Box::pin(mailbox.serve(target.clone()));
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
            assert_eq!(request, target);
            drop(response);

            match receiver.recv().await.expect("cancel should be queued") {
                Message::CancelState { request } => {
                    assert_eq!(request, target);
                }
                Message::AttachDatabase(_) => panic!("unexpected attach message"),
                Message::GetState { .. } => panic!("unexpected duplicate request"),
            }
        });
    }
}
