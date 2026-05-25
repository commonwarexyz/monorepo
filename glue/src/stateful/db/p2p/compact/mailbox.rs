//! Mailbox for the compact QMDB P2P resolver.

use super::handler;
use crate::stateful::db::AttachableResolver;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{merkle::Family, qmdb::sync::compact};
use commonware_utils::{channel::oneshot, sync::AsyncRwLock};
use std::{collections::VecDeque, future::Future, sync::Arc};

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

pub(super) enum Message<DB, F: Family, Op, D: Digest> {
    AttachDatabase(Arc<AsyncRwLock<DB>>),
    GetState {
        request: handler::Request<F, D>,
        response: oneshot::Sender<Result<compact::FetchResult<F, Op, D>, ResponseDropped>>,
    },
}

impl<DB, F: Family, Op, D: Digest> Message<DB, F, Op, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachDatabase(_) => false,
            Self::GetState { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<DB, F: Family, Op, D: Digest> {
    database: Option<Arc<AsyncRwLock<DB>>>,
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
    pub fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        let _ = self.sender.enqueue(Message::AttachDatabase(db));
    }
}

impl<DB, F, Op, H> compact::Resolver for Mailbox<DB, F, Op, H>
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

    async fn get_compact_state(
        &self,
        target: compact::Target<Self::Family, Self::Digest>,
    ) -> Result<compact::FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let request = handler::Request::from_target(target);
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetState { request, response });
        receiver.await.map_err(|_| ResponseDropped)?
    }
}

impl<DB, F, Op, H> AttachableResolver<DB> for Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) -> impl Future<Output = ()> + Send {
        Self::attach_database(self, db);
        std::future::ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_storage::{mmr, qmdb::sync::compact::Resolver as _};
    use commonware_utils::NZUsize;

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
}
