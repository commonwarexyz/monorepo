//! Finalization handler for resolver integration.
//!
//! Implements Consumer and Producer traits as a simple forwarder to the
//! orchestrator actor. All validation logic lives in the actor.

use bytes::Bytes;
use commonware_consensus::types::Epoch;
use commonware_resolver::{p2p::Producer, Consumer};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent from the resolver's Consumer/Producer to the orchestrator actor.
#[derive(Debug)]
pub enum Message {
    /// A request to deliver a value for a given key.
    Deliver {
        /// The epoch of the finalization being delivered.
        epoch: Epoch,
        /// The raw bytes of the finalization response.
        value: Bytes,
        /// A channel to send the result of the delivery (true for valid data).
        response: oneshot::Sender<bool>,
    },
    /// A request to produce a value for a given key.
    Produce {
        /// The epoch of the finalization to produce.
        epoch: Epoch,
        /// A channel to send the produced value.
        response: oneshot::Sender<Bytes>,
    },
}

/// Handler for finalization requests, implementing both Consumer and Producer.
///
/// This is a simple forwarder that sends messages to the orchestrator actor.
/// All validation logic lives in the actor's select loop.
#[derive(Clone)]
pub struct Handler {
    sender: mpsc::Sender<Message>,
}

impl Handler {
    /// Create a new handler.
    pub const fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = Epoch;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Deliver {
                epoch: key,
                value,
                response,
            })
            .await
            .is_err()
        {
            error!("failed to send deliver message to actor");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    async fn failed(&mut self, key: Self::Key, _failure: Self::Failure) {
        // We don't need to do anything on failure, the resolver will retry.
        // The actor tracks fetching_epoch and will handle cleanup on cancel/success.
        tracing::debug!(epoch = %key, "finalization fetch failed");
    }
}

impl Producer for Handler {
    type Key = Epoch;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Produce {
                epoch: key,
                response,
            })
            .await
            .is_err()
        {
            error!("failed to send produce message to actor");
        }
        receiver
    }
}
