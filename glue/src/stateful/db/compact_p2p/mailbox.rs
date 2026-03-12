//! Mailbox for the compact QMDB P2P resolver.

use super::handler;
use crate::stateful::db::AttachableResolver;
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{merkle::Family, qmdb::sync::compact};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    sync::AsyncRwLock,
};
use std::sync::Arc;

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

pub(super) enum Message<DB, F: Family, Op, D: Digest> {
    AttachDatabase(Arc<AsyncRwLock<DB>>),
    GetState {
        request: handler::Request<F, D>,
        response: oneshot::Sender<Result<compact::State<F, Op, D>, ResponseDropped>>,
    },
}

/// Client-facing resolver mailbox used by compact QMDB sync.
pub struct Mailbox<DB, F: Family, Op, H: Hasher> {
    sender: mpsc::Sender<Message<DB, F, Op, H::Digest>>,
}

impl<DB, F: Family, Op, H: Hasher> Clone for Mailbox<DB, F, Op, H> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<DB, F: Family, Op, H: Hasher> Mailbox<DB, F, Op, H> {
    pub(super) const fn new(sender: mpsc::Sender<Message<DB, F, Op, H::Digest>>) -> Self {
        Self { sender }
    }
}

impl<DB: Send + Sync, F: Family, Op: Send, H: Hasher> Mailbox<DB, F, Op, H> {
    pub async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.sender.send_lossy(Message::AttachDatabase(db)).await;
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
    ) -> Result<compact::State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let request = handler::Request::from_target(target);
        self.sender
            .request(|response| Message::GetState { request, response })
            .await
            .ok_or(ResponseDropped)?
    }
}

impl<DB, F, Op, H> AttachableResolver<DB> for Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.attach_database(db).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_storage::{mmr, qmdb::sync::compact::Resolver as _};

    #[test]
    fn get_compact_state_sends_request() {
        deterministic::Runner::default().start(|_| async move {
            let (sender, mut receiver) = mpsc::channel(4);
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
