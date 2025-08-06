use crate::{Artifact, Artifactable, Block, Collection, Reporter};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// Messages sent to the marshal [Actor](super::super::actor::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
#[allow(dead_code)] // Some variants may not be used during refactoring
pub(crate) enum Message<B: Block, A: Artifactable> {
    // -------------------- Application Messages --------------------
    /// A request to retrieve a block by its digest.
    Get {
        /// The digest of the block to retrieve.
        commitment: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<B>>,
    },
    /// A request to retrieve a block by its digest.
    Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        view: Option<u64>,
        /// The digest of the block to retrieve.
        commitment: B::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<B>,
    },
    /// A request to broadcast a block to all peers.
    Broadcast {
        /// The block to broadcast.
        block: B,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The view in which the block was verified.
        view: u64,
        /// The verified block.
        block: B,
    },

    // -------------------- Consensus Engine Messages --------------------
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: <A::Collection as Collection>::Notarization,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: <A::Collection as Collection>::Finalization,
    },
}

/// A mailbox for sending messages to the marshal [Actor](super::super::actor::Actor).
#[derive(Clone)]
pub struct Mailbox<B: Block, A: Artifactable> {
    sender: mpsc::Sender<Message<B, A>>,
}

impl<B: Block, A: Artifactable> Mailbox<B, A> {
    /// Creates a new mailbox.
    pub(crate) fn new(sender: mpsc::Sender<Message<B, A>>) -> Self {
        Self { sender }
    }

    /// Get is a best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get(&mut self, commitment: B::Commitment) -> oneshot::Receiver<Option<B>> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Get {
                commitment,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send get message to actor: receiver dropped");
        }
        rx
    }

    /// Subscribe is a request to retrieve a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub async fn subscribe(
        &mut self,
        view: Option<u64>,
        commitment: B::Commitment,
    ) -> oneshot::Receiver<B> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Message::Subscribe {
                view,
                commitment,
                response: tx,
            })
            .await
            .is_err()
        {
            error!("failed to send subscribe message to actor: receiver dropped");
        }
        rx
    }

    /// Broadcast indicates that a block should be sent to all peers.
    pub async fn broadcast(&mut self, block: B) {
        if self
            .sender
            .send(Message::Broadcast { block })
            .await
            .is_err()
        {
            error!("failed to send broadcast message to actor: receiver dropped");
        }
    }

    /// Notifies the actor that a block has been verified.
    pub async fn verified(&mut self, view: u64, block: B) {
        if self
            .sender
            .send(Message::Verified { view, block })
            .await
            .is_err()
        {
            error!("failed to send verified message to actor: receiver dropped");
        }
    }
}

impl<B: Block, A: Artifactable> Reporter for Mailbox<B, A> {
    type Activity = A;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity.artifact() {
            Artifact::Notarization(notarization) => Message::Notarization { notarization },
            Artifact::Finalization(finalization) => Message::Finalization { finalization },
            _ => return,
        };

        if let Err(e) = self.sender.send(message).await {
            error!("failed to send message to actor: {}", e);
        }
    }
}
