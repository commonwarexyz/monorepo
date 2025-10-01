//! Mailbox for the shard layer actor

use super::types::CodedBlock;
use crate::{
    marshal::coding::actor::ReconstructionError,
    threshold_simplex::types::{Activity, Notarize},
    types::CodingCommitment,
    Block, Reporter,
};
use commonware_coding::Scheme;
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

/// A message that can be sent to the [Actor].
///
/// [Actor]: super::Actor
pub enum Message<V, B, S, P>
where
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
{
    /// Broadcast an erasure coded block's shards to a set of peers.
    Broadcast {
        /// The erasure coded block.
        block: CodedBlock<B, S>,
        /// The peers to broadcast the shards to.
        peers: Vec<P>,
    },
    /// Verifies a shard at a given commitment and index. If the shard is valid, it will be
    /// broadcasted to all peers.
    VerifyShard {
        /// The [CodingCommitment] for the block the shard belongs to.
        commitment: CodingCommitment,
        /// The index of the shard in the erasure coded block.
        index: usize,
        /// A response channel to send the result to.
        response: oneshot::Sender<bool>,
    },
    /// Attempt to reconstruct a block from received shards.
    TryReconstruct {
        /// The [CodingCommitment] for the block to reconstruct.
        commitment: CodingCommitment,
        /// A response channel to send the reconstructed block to.
        #[allow(clippy::type_complexity)]
        response: oneshot::Sender<Result<Option<CodedBlock<B, S>>, ReconstructionError<S>>>,
    },
    /// Subscribe to notifications for when a block is fully reconstructed.
    SubscribeBlock {
        /// The [CodingCommitment] for the block to subscribe to.
        commitment: CodingCommitment,
        /// A response channel to send the reconstructed block to.
        response: oneshot::Sender<CodedBlock<B, S>>,
    },
    /// A notarization vote to be processed.
    Notarize {
        /// The notarization vote.
        notarization: Notarize<V, B::Commitment>,
    },
    /// A notice that a block has been finalized.
    Finalized {
        /// The [CodingCommitment] for the finalized block.
        commitment: CodingCommitment,
    },
}

/// A mailbox for sending messages to the [Actor].
///
/// [Actor]: super::Actor
#[derive(Clone)]
pub struct Mailbox<V, B, S, P>
where
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
{
    sender: mpsc::Sender<Message<V, B, S, P>>,
}

impl<V, B, S, P> Mailbox<V, B, S, P>
where
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
{
    /// Create a new [Mailbox] with the given sender.
    pub fn new(sender: mpsc::Sender<Message<V, B, S, P>>) -> Self {
        Self { sender }
    }

    /// Broadcast an erasure coded block's shards to a set of peers.
    pub async fn broadcast(&mut self, block: CodedBlock<B, S>, peers: Vec<P>) {
        let msg = Message::Broadcast { block, peers };
        self.sender.send(msg).await.expect("mailbox closed");
    }

    /// Broadcast an individual shard to all peers.
    pub async fn verify_shard(
        &mut self,
        commitment: CodingCommitment,
        index: usize,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::VerifyShard {
            commitment,
            index,
            response: tx,
        };
        self.sender.send(msg).await.expect("mailbox closed");

        rx
    }

    /// Attempt to reconstruct a block from received shards.
    pub async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> oneshot::Receiver<Result<Option<CodedBlock<B, S>>, ReconstructionError<S>>> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::TryReconstruct {
            commitment,
            response: tx,
        };
        self.sender.send(msg).await.expect("mailbox closed");

        rx
    }

    /// Subscribe to notifications for when a block is fully reconstructed.
    pub async fn subscribe_block(
        &mut self,
        commitment: CodingCommitment,
    ) -> oneshot::Receiver<CodedBlock<B, S>> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeBlock {
            commitment,
            response: tx,
        };
        self.sender.send(msg).await.expect("mailbox closed");

        rx
    }

    /// A notice that a block has been finalized.
    pub async fn finalized(&mut self, commitment: CodingCommitment) {
        let msg = Message::Finalized { commitment };
        self.sender.send(msg).await.expect("mailbox closed");
    }
}

impl<V, B, S, P> Reporter for Mailbox<V, B, S, P>
where
    V: Variant,
    B: Block<Commitment = CodingCommitment>,
    S: Scheme,
    P: PublicKey,
{
    type Activity = Activity<V, B::Commitment>;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity {
            Activity::Notarize(notarization) => Message::Notarize { notarization },
            _ => {
                // Ignore other activity types
                return;
            }
        };
        if self.sender.send(message).await.is_err() {
            error!("failed to report activity to actor: receiver dropped");
        }
    }
}
