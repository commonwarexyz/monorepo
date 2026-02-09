//! Mailbox for the shard buffer engine.

use crate::{
    marshal::coding::types::CodedBlock,
    types::{CodingCommitment, View},
    CertifiableBlock,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    ordered::Set,
};
use std::sync::Arc;

/// A message that can be sent to the coding [`Engine`].
///
/// [`Engine`]: super::Engine
pub enum Message<B, C, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    P: PublicKey,
{
    /// A request to update the participant set.
    UpdateParticipants { me: P, participants: Set<P> },
    /// A request to broadcast a proposed [`CodedBlock`] to all peers.
    Proposed {
        /// The erasure coded block.
        block: CodedBlock<B, C>,
    },
    /// A notification from consensus that a [`CodingCommitment`] was externally proposed.
    ExternalProposed {
        /// The [`CodingCommitment`] of the proposed block.
        commitment: CodingCommitment,
        /// The leader's public key.
        leader: P,
        /// The view in which the commitment was proposed.
        view: View,
    },
    /// A request to get a reconstructed block, if available.
    GetByCommitment {
        /// The [`CodingCommitment`] of the block to get.
        commitment: CodingCommitment,
        /// The response channel.
        response: oneshot::Sender<Option<Arc<CodedBlock<B, C>>>>,
    },
    /// A request to get a reconstructed block by its digest, if available.
    GetByDigest {
        /// The digest of the block to get.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Option<Arc<CodedBlock<B, C>>>>,
    },
    /// A request to open a subscription for the receipt of our valid shard from
    /// the leader.
    SubscribeShard {
        /// The block's commitment.
        commitment: CodingCommitment,
        /// The response channel.
        response: oneshot::Sender<()>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its [`CodingCommitment`].
    SubscribeBlockByCommitment {
        /// The block's digest.
        commitment: CodingCommitment,
        /// The response channel.
        response: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its digest.
    SubscribeBlockByDigest {
        /// The block's digest.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Arc<CodedBlock<B, C>>>,
    },
    /// A notification from marshal that a reconstructed block has been made durable.
    Durable {
        /// The block's [`CodingCommitment`].
        commitment: CodingCommitment,
    },
}

/// A mailbox for sending messages to the [`Engine`].
///
/// [`Engine`]: super::Engine
#[derive(Clone)]
pub struct Mailbox<B, C, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    P: PublicKey,
{
    pub(super) sender: mpsc::Sender<Message<B, C, P>>,
}

impl<B, C, P> Mailbox<B, C, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    P: PublicKey,
{
    /// Create a new [`Mailbox`] with the given sender.
    pub const fn new(sender: mpsc::Sender<Message<B, C, P>>) -> Self {
        Self { sender }
    }

    /// Update the participant set.
    pub async fn update_participants(&mut self, me: P, participants: Set<P>) {
        let msg = Message::UpdateParticipants { me, participants };
        self.sender.send_lossy(msg).await;
    }

    /// Broadcast a proposed erasure coded block's shards to the participants.
    pub async fn proposed(&mut self, block: CodedBlock<B, C>) {
        let msg = Message::Proposed { block };
        self.sender.send_lossy(msg).await;
    }

    /// Inform the engine of an externally proposed [`CodingCommitment`].
    pub async fn external_proposed(&mut self, commitment: CodingCommitment, leader: P, view: View) {
        let msg = Message::ExternalProposed {
            commitment,
            leader,
            view,
        };
        self.sender.send_lossy(msg).await;
    }

    /// Request a reconstructed block by its [`CodingCommitment`].
    pub async fn get(&mut self, commitment: CodingCommitment) -> Option<Arc<CodedBlock<B, C>>> {
        self.sender
            .request(|tx| Message::GetByCommitment {
                commitment,
                response: tx,
            })
            .await
            .flatten()
    }

    /// Request a reconstructed block by its digest.
    pub async fn get_by_digest(&mut self, digest: B::Digest) -> Option<Arc<CodedBlock<B, C>>> {
        self.sender
            .request(|tx| Message::GetByDigest {
                digest,
                response: tx,
            })
            .await
            .flatten()
    }

    /// Subscribe to the receipt of our valid shard from the leader.
    pub async fn subscribe_shard(&mut self, commitment: CodingCommitment) -> oneshot::Receiver<()> {
        let (responder, receiver) = oneshot::channel();
        let msg = Message::SubscribeShard {
            commitment,
            response: responder,
        };
        self.sender.send_lossy(msg).await;
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its [`CodingCommitment`].
    pub async fn subscribe_block(
        &mut self,
        commitment: CodingCommitment,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C>>> {
        let (responder, receiver) = oneshot::channel();
        let msg = Message::SubscribeBlockByCommitment {
            commitment,
            response: responder,
        };
        self.sender.send_lossy(msg).await;
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its digest.
    pub async fn subscribe_block_by_digest(
        &mut self,
        digest: B::Digest,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C>>> {
        let (responder, receiver) = oneshot::channel();
        let msg = Message::SubscribeBlockByDigest {
            digest,
            response: responder,
        };
        self.sender.send_lossy(msg).await;
        receiver
    }

    /// Notify the engine that a reconstructed block has been made durable.
    pub async fn durable(&mut self, commitment: CodingCommitment) {
        let msg = Message::Durable { commitment };
        self.sender.send_lossy(msg).await;
    }
}
