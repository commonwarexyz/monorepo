//! Mailbox for the compact QMDB P2P resolver.

use super::handler;
use crate::stateful::db::AttachableResolver;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{merkle::Family, qmdb::sync::compact};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, future::Future};

struct CancelGuard<Src, F: Family, Op, D: Digest> {
    sender: Sender<Message<Src, F, Op, D>>,
    request: Option<handler::Request<F, D>>,
}

impl<Src, F: Family, Op, D: Digest> CancelGuard<Src, F, Op, D> {
    const fn new(sender: Sender<Message<Src, F, Op, D>>, request: handler::Request<F, D>) -> Self {
        Self {
            sender,
            request: Some(request),
        }
    }

    const fn disarm(&mut self) {
        self.request = None;
    }
}

impl<Src, F: Family, Op, D: Digest> Drop for CancelGuard<Src, F, Op, D> {
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

pub(super) enum Message<Src, F: Family, Op, D: Digest> {
    AttachSource(Src),
    GetState {
        request: handler::Request<F, D>,
        response: oneshot::Sender<Result<compact::FetchResult<F, Op, D>, ResponseDropped>>,
    },
    CancelState {
        request: handler::Request<F, D>,
    },
}

impl<Src, F: Family, Op, D: Digest> Message<Src, F, Op, D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::AttachSource(_) | Self::CancelState { .. } => false,
            Self::GetState { response, .. } => response.is_closed(),
        }
    }
}

pub(super) struct Pending<Src, F: Family, Op, D: Digest> {
    source: Option<Src>,
    messages: VecDeque<Message<Src, F, Op, D>>,
}

impl<Src, F: Family, Op, D: Digest> Default for Pending<Src, F, Op, D> {
    fn default() -> Self {
        Self {
            source: None,
            messages: VecDeque::new(),
        }
    }
}

impl<Src, F: Family, Op, D: Digest> Overflow<Message<Src, F, Op, D>> for Pending<Src, F, Op, D> {
    fn is_empty(&self) -> bool {
        self.source.is_none() && self.messages.is_empty()
    }

    fn drain<P>(&mut self, mut push: P)
    where
        P: FnMut(Message<Src, F, Op, D>) -> Option<Message<Src, F, Op, D>>,
    {
        if let Some(source) = self.source.take()
            && let Some(Message::AttachSource(source)) = push(Message::AttachSource(source))
        {
            self.source = Some(source);
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

impl<Src, F: Family, Op, D: Digest> Policy for Message<Src, F, Op, D> {
    type Overflow = Pending<Src, F, Op, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        match message {
            Self::AttachSource(source) => {
                overflow.source = Some(source);
            }
            message => overflow.messages.push_back(message),
        }
    }
}

/// Client-facing resolver mailbox used by compact QMDB sync.
pub struct Mailbox<Src, F: Family, Op, H: Hasher> {
    sender: Sender<Message<Src, F, Op, H::Digest>>,
}

impl<Src, F: Family, Op, H: Hasher> Clone for Mailbox<Src, F, Op, H> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<Src, F: Family, Op, H: Hasher> Mailbox<Src, F, Op, H> {
    pub(super) const fn new(sender: Sender<Message<Src, F, Op, H::Digest>>) -> Self {
        Self { sender }
    }
}

impl<Src: Send + Sync, F: Family, Op: Send, H: Hasher> Mailbox<Src, F, Op, H> {
    /// Attach a serving source; queued attaches coalesce so only the latest survives.
    pub fn attach_source(&self, source: Src) {
        let _ = self.sender.enqueue(Message::AttachSource(source));
    }
}

impl<Src, F, Op, H> compact::Resolver for Mailbox<Src, F, Op, H>
where
    Src: Send + Sync + 'static,
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

impl<Src, F, Op, H> AttachableResolver<Src> for Mailbox<Src, F, Op, H>
where
    Src: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    fn attach_source(&self, source: Src) -> impl Future<Output = ()> + Send {
        Self::attach_source(self, source);
        std::future::ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_storage::{mmr, qmdb::sync::compact::Resolver as _};
    use commonware_utils::NZUsize;
    use futures::future::poll_fn;
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
                Message::AttachSource(_) => panic!("unexpected attach message"),
                Message::GetState { .. } => panic!("unexpected duplicate request"),
            }
        });
    }
}
