//! Mailbox for the shard buffer engine.

use crate::{
    marshal::coding::{shards::ReconstructionError, types::CodedBlock},
    simplex::types::{Activity, Notarize},
    types::CodingCommitment,
    Block, Reporter, Scheme,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{mpsc, oneshot},
    Participant,
};
use std::sync::Arc;
use tracing::error;

/// A message that can be sent to the coding [Engine].
///
/// [Engine]: super::Engine
pub enum Message<B, S, C, P>
where
    B: Block,
    S: Scheme,
    C: CodingScheme,
    P: PublicKey,
{
    /// A request to broadcast a proposed [CodedBlock] to all peers.
    Proposed {
        /// The erasure coded block.
        block: CodedBlock<B, C>,
        /// The peers to broadcast the shards to.
        peers: Vec<P>,
    },
    /// Subscribes to and verifies a shard at a given commitment and index.
    /// If the shard is valid, it will be broadcasted to all peers.
    SubscribeShardValidity {
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
        response: oneshot::Sender<Result<Option<Arc<CodedBlock<B, C>>>, ReconstructionError<C>>>,
    },
    /// Subscribe to notifications for when a block is fully reconstructed, by digest.
    ///
    /// This subscription cannot trigger shard reconstruction since we don't have
    /// the full commitment needed.
    SubscribeBlockByDigest {
        /// The digest of the block to subscribe to.
        digest: B::Digest,
        /// A response channel to send the reconstructed block to.
        response: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    },
    /// Subscribe to notifications for when a block is fully reconstructed, by commitment.
    ///
    /// Having the commitment enables shard reconstruction when enough shards are available.
    SubscribeBlockByCommitment {
        /// The [CodingCommitment] for the block to subscribe to.
        commitment: CodingCommitment,
        /// A response channel to send the reconstructed block to.
        response: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    },
    /// A notarization vote to be processed.
    Notarize {
        /// The notarization vote.
        notarization: Notarize<S, CodingCommitment>,
    },
    /// A notice that a block has been finalized.
    Finalized {
        /// The [CodingCommitment] for the finalized block.
        commitment: CodingCommitment,
    },
}

/// A mailbox for sending messages to the [Engine].
///
/// [Engine]: super::Engine
#[derive(Clone)]
pub struct Mailbox<B, S, C, P>
where
    B: Block,
    S: Scheme,
    C: CodingScheme,
    P: PublicKey,
{
    pub(super) sender: mpsc::Sender<Message<B, S, C, P>>,
}

impl<B, S, C, P> Mailbox<B, S, C, P>
where
    B: Block,
    S: Scheme,
    C: CodingScheme,
    P: PublicKey,
{
    /// Create a new [Mailbox] with the given sender.
    pub const fn new(sender: mpsc::Sender<Message<B, S, C, P>>) -> Self {
        Self { sender }
    }

    /// Broadcast a proposed erasure coded block's shards to a set of peers.
    pub async fn proposed(&mut self, block: CodedBlock<B, C>, peers: Vec<P>) {
        let msg = Message::Proposed { block, peers };
        self.sender.send(msg).await.expect("mailbox closed");
    }

    /// Subscribe to and verify a shard at a given commitment and index.
    pub async fn subscribe_shard_validity(
        &mut self,
        commitment: CodingCommitment,
        index: Participant,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeShardValidity {
            commitment,
            index: index.get() as usize,
            response: tx,
        };
        self.sender.send(msg).await.expect("mailbox closed");

        rx
    }

    /// Attempt to reconstruct a block from received shards.
    pub async fn try_reconstruct(
        &mut self,
        commitment: CodingCommitment,
    ) -> Result<Option<Arc<CodedBlock<B, C>>>, ReconstructionError<C>> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::TryReconstruct {
            commitment,
            response: tx,
        };
        self.sender.send(msg).await.expect("mailbox closed");

        rx.await.expect("mailbox closed")
    }

    /// Subscribe to notifications for when a block is fully reconstructed, by digest.
    ///
    /// This subscription cannot trigger shard reconstruction since we don't have
    /// the full commitment needed.
    pub async fn subscribe_block_by_digest(
        &mut self,
        digest: B::Digest,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C>>> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeBlockByDigest {
            digest,
            response: tx,
        };
        self.sender.send(msg).await.expect("mailbox closed");

        rx
    }

    /// Subscribe to notifications for when a block is fully reconstructed, by commitment.
    ///
    /// Having the commitment enables shard reconstruction when enough shards are available.
    pub async fn subscribe_block_by_commitment(
        &mut self,
        commitment: CodingCommitment,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C>>> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::SubscribeBlockByCommitment {
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

impl<B, S, C, P> Reporter for Mailbox<B, S, C, P>
where
    B: Block,
    S: Scheme,
    C: CodingScheme,
    P: PublicKey,
{
    type Activity = Activity<S, CodingCommitment>;

    async fn report(&mut self, activity: Self::Activity) {
        let message = match activity {
            Activity::Notarize(notarization) => Message::Notarize { notarization },
            _ => {
                // Ignore other activity types
                return;
            }
        };
        if self.sender.send(message).await.is_err() {
            error!("failed to report activity to shard engine: receiver dropped");
        }
    }
}
