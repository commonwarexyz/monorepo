//! Mailbox and message types for the resolver actor.

use crate::{minimmit::types::Certificate, types::View};
use bytes::Bytes;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    sequence::U64,
};

/// Messages that can be sent to the resolver actor.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received and should be tracked.
    Certificate(Certificate<S, D>),
}

/// Mailbox for sending messages to the resolver actor.
#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox with the given sender.
    pub const fn new(sender: mpsc::Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Forward a certificate to the resolver.
    pub async fn updated(&mut self, certificate: Certificate<S, D>) {
        self.sender
            .send_lossy(MailboxMessage::Certificate(certificate))
            .await;
    }
}

/// Messages sent from the Handler to the resolver actor.
#[derive(Debug)]
pub enum HandlerMessage {
    /// A response was received from a peer.
    Deliver {
        view: View,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    /// A peer is requesting data for a view.
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

/// Handler bridges the resolver engine with the resolver actor.
///
/// Implements Consumer and Producer traits for the p2p resolver engine.
#[derive(Clone)]
pub struct Handler {
    sender: mpsc::Sender<HandlerMessage>,
}

impl Handler {
    /// Create a new handler with the given sender.
    pub const fn new(sender: mpsc::Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;
    type Failure = ();

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

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {
        // We don't need to do anything on failure, the resolver will retry.
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
