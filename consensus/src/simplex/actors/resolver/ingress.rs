use crate::{simplex::types::Certificate, types::View};
use bytes::Bytes;
use commonware_actor::mailbox::{Policy, Sender};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    sequence::U64,
};
use std::collections::VecDeque;

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced.
    Certificate(Certificate<S, D>),
    /// Certification result for a view.
    Certified { view: View, success: bool },
}

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message {
            Self::Certificate(_) => {
                overflow.push_back(message);
                true
            }
            Self::Certified { .. } => {
                overflow.push_back(message);
                true
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub fn updated(&mut self, certificate: Certificate<S, D>) {
        let _ = self
            .sender
            .enqueue(MailboxMessage::Certificate(certificate));
    }

    /// Notify the resolver of a certification result.
    pub fn certified(&mut self, view: View, success: bool) {
        let _ = self
            .sender
            .enqueue(MailboxMessage::Certified { view, success });
    }
}

#[derive(Debug)]
pub enum HandlerMessage {
    Deliver {
        view: View,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

#[derive(Clone)]
pub struct Handler {
    sender: mpsc::Sender<HandlerMessage>,
}

impl Handler {
    pub const fn new(sender: mpsc::Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        self.sender
            .request_or(
                |response| HandlerMessage::Deliver {
                    view: View::new(key.into()),
                    data: value,
                    response,
                },
                false,
            )
            .await
    }
}

impl Producer for Handler {
    type Key = U64;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(HandlerMessage::Produce {
                view: View::new(key.into()),
                response,
            })
            .await;
        receiver
    }
}
