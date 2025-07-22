use bytes::Bytes;
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent from the resolver's [`Consumer`]/[`Producer`] implementation
/// to the marshal [`Actor`](super::actor::Actor).
pub enum Message<K: Array> {
    /// A request to deliver a value for a given key.
    Deliver {
        /// The key of the value being delivered.
        key: K,
        /// The value being delivered.
        value: Bytes,
        /// A channel to send the result of the delivery (true for success).
        response: oneshot::Sender<bool>,
    },
    /// A request to produce a value for a given key.
    Produce {
        /// The key of the value to produce.
        key: K,
        /// A channel to send the produced value.
        response: oneshot::Sender<Bytes>,
    },
}

/// A handler that forwards requests from the resolver to the marshal actor.
///
/// This struct implements the [`Consumer`] and [`Producer`] traits from the
/// resolver, and acts as a bridge to the main actor loop.
#[derive(Clone)]
pub struct Handler<K: Array> {
    sender: mpsc::Sender<Message<K>>,
}

impl<K: Array> Handler<K> {
    /// Creates a new handler.
    pub(super) fn new(sender: mpsc::Sender<Message<K>>) -> Self {
        Self { sender }
    }
}

impl<K: Array> Consumer for Handler<K> {
    type Key = K;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Deliver {
                key,
                value,
                response,
            })
            .await
            .is_err()
        {
            error!("Failed to send deliver message to actor: receiver dropped");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {
        // We don't need to do anything on failure, the resolver will retry.
    }
}

impl<K: Array> Producer for Handler<K> {
    type Key = K;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Produce { key, response })
            .await
            .is_err()
        {
            error!("Failed to send produce message to actor: receiver dropped");
        }
        receiver
    }
}
