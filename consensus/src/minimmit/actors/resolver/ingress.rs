//! Mailbox and message types for the resolver actor.

use crate::{minimmit::types::Certificate, types::View};
use bytes::Bytes;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::sequence::U64;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced by the voter.
    Updated(Certificate<S, D>),
}

/// Mailbox for sending messages to the resolver actor.
#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mpsc::Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Notifies the resolver that a certificate has been received/created.
    ///
    /// This is called by the voter when it assembles or receives a certificate.
    pub async fn updated(&mut self, certificate: Certificate<S, D>) {
        if let Err(err) = self.sender.send(MailboxMessage::Updated(certificate)).await {
            error!(?err, "failed to send certificate message");
        }
    }
}

/// Messages from the p2p resolver engine.
#[derive(Debug)]
pub enum HandlerMessage {
    /// A certificate was received from a peer.
    Deliver {
        view: View,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    /// A peer is requesting a certificate for a view.
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

/// Handler for p2p resolver engine callbacks.
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
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(HandlerMessage::Deliver {
                view: View::new(key.into()),
                data: value,
                response,
            })
            .await
            .is_err()
        {
            error!("failed to deliver resolver message to actor");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {
        // We don't need to do anything on failure, the resolver will retry.
    }
}

impl Producer for Handler {
    type Key = U64;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(HandlerMessage::Produce {
                view: View::new(key.into()),
                response,
            })
            .await
            .is_err()
        {
            error!("failed to send produce request to actor");
        }
        receiver
    }
}
