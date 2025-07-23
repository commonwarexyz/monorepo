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

/// Messages sent to the marshal [`Actor`](super::actor::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub enum Message<V: Variant, B: Block> {
    /// A request to retrieve a block by its digest.
    Get {
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
    /// A notification that a block has been verified by the consensus engine.
    Verified {
        /// The view in which the block was verified.
        view: u64,
        /// The verified block.
        payload: B,
    },
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

/// A mailbox for sending messages to the marshal [`Actor`](super::actor::Actor).
#[derive(Clone)]
pub struct Mailbox<V: Variant, B: Block> {
    sender: mpsc::Sender<Message<V, B>>,
}

impl<V: Variant, B: Block> Mailbox<V, B> {
    /// Creates a new mailbox.
    pub(super) fn new(sender: mpsc::Sender<Message<V, B>>) -> Self {
        Self { sender }
    }

    /// Get is a best-effort attempt to retrieve a given payload from local
    /// storage. It is not an indication to go fetch the payload from the network.
    pub async fn get(&mut self, view: Option<u64>, payload: B::Commitment) -> oneshot::Receiver<B> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Get {
                view,
                payload,
                response,
            })
            .await
            .is_err()
        {
            error!("Failed to send get message to actor: receiver dropped");
        }
        receiver
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

/// Messages sent from the finalizer task to the main actor loop.
///
/// We break this into a separate enum to establish a separate priority for
/// finalizer messages over consensus messages.
pub enum Orchestration<B: Block> {
    /// A request to get the next finalized block.
    Get {
        /// The height of the block to get.
        next: u64,
        /// A channel to send the block, if found.
        result: oneshot::Sender<Option<B>>,
    },
    /// A notification that a block has been processed by the application.
    Processed {
        /// The height of the processed block.
        next: u64,
        /// The digest of the processed block.
        digest: B::Commitment,
    },
    /// A request to repair a gap in the finalized block sequence.
    Repair {
        /// The height at which to start repairing.
        next: u64,
        /// A channel to send the result of the repair attempt (true if a block
        /// was repaired).
        result: oneshot::Sender<bool>,
    },
}

/// A handle for the finalizer to communicate with the main actor loop.
#[derive(Clone)]
pub struct Orchestrator<B: Block> {
    sender: mpsc::Sender<Orchestration<B>>,
}

impl<B: Block> Orchestrator<B> {
    /// Creates a new orchestrator.
    pub fn new(sender: mpsc::Sender<Orchestration<B>>) -> Self {
        Self { sender }
    }

    /// Gets the finalized block at the given height.
    pub async fn get(&mut self, next: u64) -> Option<B> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Orchestration::Get {
                next,
                result: response,
            })
            .await
            .is_err()
        {
            error!("Failed to send get message to actor: receiver dropped");
            return None;
        }
        receiver.await.unwrap_or(None)
    }

    /// Notifies the actor that a block has been processed.
    pub async fn processed(&mut self, next: u64, digest: B::Commitment) {
        if self
            .sender
            .send(Orchestration::Processed { next, digest })
            .await
            .is_err()
        {
            error!("Failed to send processed message to actor: receiver dropped");
        }
    }

    /// Attempts to repair a gap in the block sequence.
    pub async fn repair(&mut self, next: u64) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Orchestration::Repair {
                next,
                result: response,
            })
            .await
            .is_err()
        {
            error!("Failed to send repair message to actor: receiver dropped");
            return false;
        }
        receiver.await.unwrap_or(false)
    }
}
