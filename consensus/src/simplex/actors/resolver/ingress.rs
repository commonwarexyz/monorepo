use crate::{
    simplex::{signing_scheme::Scheme, types::Certificate},
    types::View,
};
use bytes::Bytes;
use commonware_cryptography::Digest;
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::sequence::U64;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Certificate<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mpsc::Sender<Certificate<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub async fn updated(&mut self, certificate: Certificate<S, D>) {
        if let Err(err) = self.sender.send(certificate).await {
            error!(?err, "failed to send certificate message");
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
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Deliver {
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
            .send(Message::Produce {
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
