use crate::{simplex::types::Certificate, types::View};
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
    /// A certificate was received or produced.
    Certificate(Certificate<S, D>),
    /// Certification result for a view.
    Certified { view: View, success: bool },
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mpsc::Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub async fn updated(&mut self, certificate: Certificate<S, D>) {
        if let Err(err) = self
            .sender
            .send(MailboxMessage::Certificate(certificate))
            .await
        {
            error!(?err, "failed to send certificate message");
        }
    }

    /// Notify the resolver of a certification result.
    pub async fn certified(&mut self, view: View, success: bool) {
        if let Err(err) = self
            .sender
            .send(MailboxMessage::Certified { view, success })
            .await
        {
            error!(?err, "failed to send certified message");
        }
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
