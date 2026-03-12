//! Mailbox and wire types for the QMDB sync resolver service.

use super::handler;
use crate::stateful::db::AttachableResolver;
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::sync::resolver::{FetchResult, Resolver as SyncResolver},
};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    sync::AsyncRwLock,
};
use futures::FutureExt as _;
use std::{num::NonZeroU64, sync::Arc};

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Messages sent from the [`Mailbox`] to the resolver [`Actor`](super::Actor).
pub(super) enum Message<DB, F: Family, Op, D: Digest> {
    /// Provide a database handle so the actor can serve incoming requests.
    AttachDatabase(Arc<AsyncRwLock<DB>>),
    /// Fetch operations from a remote peer via the P2P resolver engine.
    GetOperations {
        request: handler::Request<F>,
        response: oneshot::Sender<Result<FetchResult<F, Op, D>, ResponseDropped>>,
    },
    /// Cancel a previously requested operation fetch.
    CancelOperations { request: handler::Request<F> },
}

/// Client-facing resolver mailbox used by the QMDB sync engine.
pub struct Mailbox<DB, F: Family, Op, D: Digest> {
    sender: mpsc::Sender<Message<DB, F, Op, D>>,
}

impl<DB, F: Family, Op, D: Digest> Clone for Mailbox<DB, F, Op, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<DB, F: Family, Op, D: Digest> Mailbox<DB, F, Op, D> {
    pub(super) const fn new(sender: mpsc::Sender<Message<DB, F, Op, D>>) -> Self {
        Self { sender }
    }
}

impl<DB: Send + Sync, F: Family, Op: Send, D: Digest> Mailbox<DB, F, Op, D> {
    pub async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.sender.send_lossy(Message::AttachDatabase(db)).await;
    }
}

impl<DB, F, Op, D> SyncResolver for Mailbox<DB, F, Op, D>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: Send + Sync + 'static,
{
    type Family = F;
    type Digest = D;
    type Op = Op;
    type Error = ResponseDropped;

    async fn get_operations(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let request = handler::Request {
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
        };

        let response = self.sender.request({
            let request = request.clone();
            move |response| Message::GetOperations { request, response }
        });

        futures::pin_mut!(response);
        futures::pin_mut!(cancel_rx);

        select! {
            response = response.as_mut() => {
                response.ok_or(ResponseDropped)?
            },
            _ = cancel_rx.as_mut() => {
                if let Some(response) = response.as_mut().now_or_never() {
                    return response.ok_or(ResponseDropped)?;
                }
                self.sender
                    .send_lossy(Message::CancelOperations { request })
                    .await;
                Err(ResponseDropped)
            },
        }
    }
}

impl<DB, F, Op, D> AttachableResolver<DB> for Mailbox<DB, F, Op, D>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: Send + Sync + 'static,
{
    async fn attach_database(&self, db: Arc<AsyncRwLock<DB>>) {
        self.attach_database(db).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_storage::mmr;
    use commonware_utils::NZU64;

    #[test]
    fn get_operations_cancellation_sends_cancel_message() {
        deterministic::Runner::default().start(|_| async move {
            let (sender, mut receiver) = mpsc::channel(4);
            let mailbox = Mailbox::<(), mmr::Family, u64, sha256::Digest>::new(sender);
            let op_count = mmr::Location::new(10);
            let start_loc = mmr::Location::new(3);
            let max_ops = NZU64!(2);

            let (cancel_tx, cancel_rx) = oneshot::channel();
            let get = mailbox.get_operations(op_count, start_loc, max_ops, false, cancel_rx);
            let observe = async move {
                let response = match receiver.recv().await.expect("request should be queued") {
                    Message::GetOperations { request, response } => {
                        assert_eq!(request.op_count, op_count);
                        assert_eq!(request.start_loc, start_loc);
                        assert_eq!(request.max_ops, max_ops);
                        assert!(!request.include_pinned_nodes);
                        response
                    }
                    Message::AttachDatabase(_) => panic!("unexpected attach message"),
                    Message::CancelOperations { .. } => panic!("cancel should come after request"),
                };

                drop(cancel_tx);

                match receiver.recv().await.expect("cancel should be queued") {
                    Message::CancelOperations { request } => {
                        assert_eq!(request.op_count, op_count);
                        assert_eq!(request.start_loc, start_loc);
                        assert_eq!(request.max_ops, max_ops);
                        assert!(!request.include_pinned_nodes);
                    }
                    Message::AttachDatabase(_) => panic!("unexpected attach message"),
                    Message::GetOperations { .. } => panic!("unexpected duplicate request"),
                }

                drop(response);
            };

            let (result, _) = futures::join!(get, observe);
            assert!(matches!(result, Err(ResponseDropped)));
        });
    }
}
