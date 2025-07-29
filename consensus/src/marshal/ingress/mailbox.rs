use crate::{
    threshold_simplex::types::{Activity, Finalization, Notarization},
    Block, Reporter,
};
use commonware_cryptography::bls12381::primitives::variant::Variant;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent to the marshal [`Actor`](super::super::actor::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub enum Message<V: Variant, B: Block> {
    // -------------------- Application Messages --------------------
    /// A request to retrieve a block by its digest.
    Get {
        /// The digest of the block to retrieve.
        payload: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<B>>,
    },
    /// A request to retrieve a block by its digest.
    Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        view: Option<u64>,
        /// The digest of the block to retrieve.
        payload: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<B>,
    },
    /// A request to broadcast a block to all peers.
    Broadcast {
        /// The block to broadcast.
        payload: B,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The view in which the block was verified.
        view: u64,
        /// The verified block.
        payload: B,
    },

    // -------------------- Consensus Engine Messages --------------------
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<V, B::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<V, B::Commitment>,
    },
}

/// A mailbox for sending messages to the marshal [`Actor`](super::super::actor::Actor).
#[derive(Clone)]
pub struct Mailbox<V: Variant, B: Block> {
    sender: mpsc::Sender<Message<V, B>>,
}

impl<V: Variant, B: Block> Mailbox<V, B> {
    /// Creates a new mailbox.
    pub fn new(sender: mpsc::Sender<Message<V, B>>) -> Self {
        Self { sender }
    }

    /// Get is a best-effort attempt to retrieve a given payload from local
    /// storage. It is not an indication to go fetch the payload from the network.
    pub async fn get(&mut self, payload: B::Commitment) -> oneshot::Receiver<Option<B>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Get {
                payload,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("Failed to send get message to actor: receiver dropped");
        }
        rx
    }

    /// Subscribe is a request to retrieve a block by its digest.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available.
    pub async fn subscribe(
        &mut self,
        view: Option<u64>,
        payload: B::Commitment,
    ) -> oneshot::Receiver<B> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Subscribe {
                view,
                payload,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("Failed to send subscribe message to actor: receiver dropped");
        }
        rx
    }

    /// Broadcast indicates that a payload should be sent to all peers.
    pub async fn broadcast(&mut self, payload: B) {
        if self
            .sender
            .send(Message::Broadcast { payload })
            .await
            .is_err()
        {
            error!("Failed to send broadcast message to actor: receiver dropped");
        }
    }

    /// Notifies the actor that a block has been verified.
    pub async fn verified(&mut self, view: u64, payload: B) {
        if self
            .sender
            .send(Message::Verified { view, payload })
            .await
            .is_err()
        {
            error!("Failed to send verified message to actor: receiver dropped");
        }
    }
}

impl<V: Variant, B: Block> Reporter for Mailbox<V, B> {
    type Activity = Activity<V, B::Commitment>;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => {
                // Ignore other activity types
                return;
            }
        };
        if self.sender.send(message).await.is_err() {
            error!("Failed to report activity to actor: receiver dropped");
        }
    }
}
