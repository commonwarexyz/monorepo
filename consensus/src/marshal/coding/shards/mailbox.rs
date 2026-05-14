//! Mailbox for the shard buffer engine.

use crate::{
    marshal::coding::types::CodedBlock,
    types::{coding::Commitment, Round},
    CertifiableBlock,
};
use commonware_actor::mailbox::{Policy, Sender};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// A message that can be sent to the coding [`Engine`].
///
/// [`Engine`]: super::Engine
pub enum Message<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// A request to broadcast a proposed [`CodedBlock`] to all peers.
    Proposed {
        /// The erasure coded block.
        block: CodedBlock<B, C, H>,
        /// The round in which the block was proposed.
        round: Round,
    },
    /// A notification from consensus that a [`Commitment`] has been discovered.
    Discovered {
        /// The [`Commitment`] of the proposed block.
        commitment: Commitment,
        /// The leader's public key.
        leader: P,
        /// The round in which the commitment was proposed.
        round: Round,
    },
    /// A request to get a reconstructed block, if available.
    GetByCommitment {
        /// The [`Commitment`] of the block to get.
        commitment: Commitment,
        /// The response channel.
        response: oneshot::Sender<Option<CodedBlock<B, C, H>>>,
    },
    /// A request to get a reconstructed block by its digest, if available.
    GetByDigest {
        /// The digest of the block to get.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Option<CodedBlock<B, C, H>>>,
    },
    /// A request to open a subscription for assigned shard verification.
    ///
    /// For participants, this resolves once the leader-delivered shard for
    /// the local participant index has been verified. Reconstructing the full
    /// block from gossiped shards does not resolve this subscription: that
    /// block may still be used for later certification, but it is not enough
    /// to claim the participant received the shard it is expected to echo.
    ///
    /// For proposers, this resolves immediately after the locally built block
    /// is cached because they trivially have all shards.
    SubscribeAssignedShardVerified {
        /// The block's commitment.
        commitment: Commitment,
        /// The response channel.
        response: oneshot::Sender<()>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its [`Commitment`].
    SubscribeByCommitment {
        /// The block's digest.
        commitment: Commitment,
        /// The response channel.
        response: oneshot::Sender<CodedBlock<B, C, H>>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its digest.
    SubscribeByDigest {
        /// The block's digest.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<CodedBlock<B, C, H>>,
    },
    /// A request to prune all caches at and below the given commitment.
    Prune {
        /// Inclusive prune target [`Commitment`].
        through: Commitment,
    },
}

impl<B, C, H, P> Policy for Message<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        overflow.push_back(message);
        true
    }
}

/// A mailbox for sending messages to the [`Engine`].
///
/// [`Engine`]: super::Engine
#[derive(Clone)]
pub struct Mailbox<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    pub(super) sender: Sender<Message<B, C, H, P>>,
}

impl<B, C, H, P> Mailbox<B, C, H, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// Create a new [`Mailbox`] with the given sender.
    pub const fn new(sender: Sender<Message<B, C, H, P>>) -> Self {
        Self { sender }
    }

    /// Broadcast a proposed erasure coded block's shards to the participants.
    pub fn proposed(&self, round: Round, block: CodedBlock<B, C, H>) {
        let msg = Message::Proposed { block, round };
        let _ = self.sender.enqueue(msg);
    }

    /// Inform the engine of an externally proposed [`Commitment`].
    pub fn discovered(&self, commitment: Commitment, leader: P, round: Round) {
        let msg = Message::Discovered {
            commitment,
            leader,
            round,
        };
        let _ = self.sender.enqueue(msg);
    }

    /// Request a reconstructed block by its [`Commitment`].
    pub async fn get(&self, commitment: Commitment) -> Option<CodedBlock<B, C, H>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetByCommitment {
            commitment,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Request a reconstructed block by its digest.
    pub async fn get_by_digest(
        &self,
        digest: B::Digest,
    ) -> Option<CodedBlock<B, C, H>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetByDigest { digest, response });
        receiver.await.ok().flatten()
    }

    /// Subscribe to assigned shard verification for a commitment.
    ///
    /// For participants, this resolves once the leader-delivered shard for
    /// the local participant index has been verified. Reconstructing the full
    /// block from gossiped shards does not resolve this subscription: that
    /// block may still be used for later certification, but it is not enough
    /// to claim the participant received the shard it is expected to echo.
    ///
    /// For proposers, this resolves immediately after the locally built block
    /// is cached because they trivially have all shards.
    pub fn subscribe_assigned_shard_verified(
        &self,
        commitment: Commitment,
    ) -> oneshot::Receiver<()> {
        let (responder, receiver) = oneshot::channel();
        let msg = Message::SubscribeAssignedShardVerified {
            commitment,
            response: responder,
        };
        let _ = self.sender.enqueue(msg);
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its [`Commitment`].
    pub fn subscribe(&self, commitment: Commitment) -> oneshot::Receiver<CodedBlock<B, C, H>> {
        let (responder, receiver) = oneshot::channel();
        let msg = Message::SubscribeByCommitment {
            commitment,
            response: responder,
        };
        let _ = self.sender.enqueue(msg);
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its digest.
    pub fn subscribe_by_digest(
        &self,
        digest: B::Digest,
    ) -> oneshot::Receiver<CodedBlock<B, C, H>> {
        let (responder, receiver) = oneshot::channel();
        let msg = Message::SubscribeByDigest {
            digest,
            response: responder,
        };
        let _ = self.sender.enqueue(msg);
        receiver
    }

    /// Request to prune all caches at and below the given commitment.
    pub fn prune(&self, through: Commitment) {
        let msg = Message::Prune { through };
        let _ = self.sender.enqueue(msg);
    }
}
