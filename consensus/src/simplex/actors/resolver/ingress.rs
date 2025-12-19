use crate::{simplex::types::Certificate, types::View};
use bytes::Bytes;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::sequence::prefixed_u64::U64 as PrefixedU64;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Prefix for regular certificate requests (any certificate type accepted).
pub const PREFIX_ANY: u8 = 0;
/// Prefix for nullification-only requests (only nullification or finalization accepted).
pub const PREFIX_NULLIFICATION_ONLY: u8 = 1;

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

#[derive(Clone)]
pub struct Handler {
    sender: mpsc::Sender<Message>,
}

impl Handler {
    pub const fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

#[derive(Debug)]
pub enum Message {
    Deliver {
        view: View,
        nullification_only: bool,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

impl Consumer for Handler {
    type Key = PrefixedU64;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        let nullification_only = key.prefix() == PREFIX_NULLIFICATION_ONLY;
        if self
            .sender
            .send(Message::Deliver {
                view: View::new(key.value()),
                nullification_only,
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
    type Key = PrefixedU64;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Produce {
                view: View::new(key.value()),
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
