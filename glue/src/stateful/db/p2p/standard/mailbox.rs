//! Mailbox and wire types for the QMDB sync resolver service.

use super::handler;
use crate::stateful::db::AttachableResolver;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_storage::{
    merkle::{Family, Location},
    qmdb::sync::resolver::{FetchResult, Provider as ResolverProvider, Resolver as SyncResolver},
};
use commonware_utils::{channel::oneshot, sync::TracedAsyncRwLock};
use futures::FutureExt as _;
use std::{collections::VecDeque, num::NonZeroU64, sync::Arc};

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

/// Messages sent from the [`Mailbox`] to the resolver [`Actor`](super::Actor).
pub(super) enum Message<R, F: Family, Op, D: Digest> {
    /// Provide a database handle so the actor can serve incoming requests.
    AttachDatabase(R),
    /// Fetch operations from a remote peer via the P2P resolver engine.
    GetOperations {
        request: handler::Request<F>,
        response: oneshot::Sender<Result<FetchResult<F, Op, D>, ResponseDropped>>,
    },
    /// Cancel a previously requested operation fetch.
    CancelOperations { request: handler::Request<F> },
}

impl<R, F: Family, Op, D: Digest> Message<R, F, Op, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachDatabase(_) | Self::CancelOperations { .. } => false,
            Self::GetOperations { response, .. } => response.is_closed(),
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

/// Client-facing resolver mailbox used by the QMDB sync engine.
pub struct Mailbox<R, F: Family, Op, D: Digest> {
    sender: Sender<Message<R, F, Op, D>>,
}

impl<R, F: Family, Op, D: Digest> Clone for Mailbox<R, F, Op, D> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<R, F: Family, Op, D: Digest> Mailbox<R, F, Op, D> {
    pub(super) const fn new(sender: Sender<Message<R, F, Op, D>>) -> Self {
        Self { sender }
    }
}

impl<R: Send + Sync, F: Family, Op: Send, D: Digest> Mailbox<R, F, Op, D> {
    pub fn attach_database(&self, resolver: R) {
        let _ = self.sender.enqueue(Message::AttachDatabase(resolver));
    }
}

impl<R, F, Op, D> SyncResolver for Mailbox<R, F, Op, D>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    R: Send + Sync + 'static,
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

        futures::pin_mut!(cancel_rx);
        let (response_tx, response_rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetOperations {
            request: request.clone(),
            response: response_tx,
        });
        futures::pin_mut!(response_rx);

        select! {
            response = response_rx.as_mut() => response.map_err(|_| ResponseDropped)?,
            _ = cancel_rx.as_mut() => {
                if let Some(response) = response_rx.as_mut().now_or_never() {
                    return response.map_err(|_| ResponseDropped)?;
                }
                let _ = self.sender.enqueue(Message::CancelOperations { request });
                Err(ResponseDropped)
            },
        }
    }
}

impl<DB, F, Op, D> AttachableResolver<DB> for Mailbox<DB::Resolver, F, Op, D>
where
    F: Family,
    Op: Read<Cfg = ()> + Send + Sync + Clone + 'static,
    D: Digest,
    DB: ResolverProvider + Send + Sync + 'static,
    DB::Resolver: SyncResolver<Family = F, Op = Op, Digest = D>,
{
    async fn attach_database(&self, db: Arc<TracedAsyncRwLock<DB>>) {
        let resolver = db.read().await.resolver();
        Self::attach_database(self, resolver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_storage::mmr;
    use commonware_utils::{NZUsize, NZU64};

    #[test]
    fn get_operations_cancellation_sends_cancel_message() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(4));
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
