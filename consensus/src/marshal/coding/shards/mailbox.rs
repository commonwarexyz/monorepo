//! Mailbox for the shard buffer engine.

use crate::{
    CertifiableBlock,
    marshal::coding::types::CodedBlock,
    types::{Round, coding::Commitment},
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::Hasher;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, sync::Arc};

/// A message that can be sent to the coding [`Engine`].
///
/// [`Engine`]: super::Engine
pub(crate) enum Message<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    /// A request to broadcast a proposed [`CodedBlock`] to all peers.
    Proposed {
        /// The erasure coded block.
        block: Arc<CodedBlock<B, C, H>>,
        /// The round in which the block was proposed.
        round: Round,
    },
    /// A notification that consensus observed a [`Commitment`], through a
    /// proposal or a notarization.
    Discovered {
        /// The [`Commitment`] of the observed block.
        commitment: Commitment<B, C, H>,
        /// The round in which the commitment was observed.
        round: Round,
    },
    /// A request to get a reconstructed block, if available.
    GetByCommitment {
        /// The [`Commitment`] of the block to get.
        commitment: Commitment<B, C, H>,
        /// The response channel.
        response: oneshot::Sender<Option<Arc<CodedBlock<B, C, H>>>>,
    },
    /// A request to get a reconstructed block by its digest, if available.
    GetByDigest {
        /// The digest of the block to get.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Option<Arc<CodedBlock<B, C, H>>>>,
    },
    /// A request to open a subscription for assigned shard verification.
    ///
    /// For participants, this resolves once the shard for the local participant
    /// index has been verified. Reconstructing the full block from gossiped
    /// shards does not resolve this subscription: that
    /// block may still be used for later certification, but it is not enough
    /// to claim the participant received the shard it is expected to echo.
    ///
    /// For proposers, this resolves immediately after the locally built block
    /// is cached because they trivially have all shards.
    ///
    /// A non-participant has no assigned shard, so its subscription never
    /// resolves.
    SubscribeAssignedShardVerified {
        /// The block's commitment.
        commitment: Commitment<B, C, H>,
        /// The response channel.
        response: oneshot::Sender<()>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its [`Commitment`].
    SubscribeByCommitment {
        /// The block's commitment.
        commitment: Commitment<B, C, H>,
        /// The response channel.
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    },
    /// A request to open a subscription for the reconstruction of a [`CodedBlock`]
    /// by its digest.
    SubscribeByDigest {
        /// The block's digest.
        digest: B::Digest,
        /// The response channel.
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    },
}

impl<B, C, H> Message<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::GetByCommitment { response, .. } | Self::GetByDigest { response, .. } => {
                response.is_closed()
            }
            Self::SubscribeAssignedShardVerified { response, .. } => response.is_closed(),
            Self::SubscribeByCommitment { response, .. }
            | Self::SubscribeByDigest { response, .. } => response.is_closed(),
            Self::Proposed { .. } | Self::Discovered { .. } => false,
        }
    }
}

pub(crate) struct Pending<B, C, H>(VecDeque<Message<B, C, H>>)
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher;

impl<B, C, H> Default for Pending<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<B, C, H> Overflow<Message<B, C, H>> for Pending<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<B, C, H>) -> Option<Message<B, C, H>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

/// Retains overflowed messages in FIFO order.
impl<B, C, H> Policy for Message<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    type Overflow = Pending<B, C, H>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        overflow.0.push_back(message);
    }
}

/// A mailbox for sending messages to the [`Engine`].
///
/// [`Engine`]: super::Engine
pub struct Mailbox<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    pub(super) sender: Sender<Message<B, C, H>>,
}

impl<B, C, H> Clone for Mailbox<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<B, C, H> Mailbox<B, C, H>
where
    B: CertifiableBlock,
    C: CodingScheme,
    H: Hasher,
{
    /// Create a new [`Mailbox`] with the given sender.
    pub(crate) const fn new(sender: Sender<Message<B, C, H>>) -> Self {
        Self { sender }
    }

    /// Broadcast a proposed erasure coded block's shards to the participants.
    pub fn proposed(&self, round: Round, block: CodedBlock<B, C, H>) {
        self.proposed_shared(round, Arc::new(block));
    }

    pub(crate) fn proposed_shared(&self, round: Round, block: Arc<CodedBlock<B, C, H>>) {
        let _ = self.sender.enqueue(Message::Proposed { block, round });
    }

    /// Inform the engine that consensus observed [`Commitment`] in `round`,
    /// through a proposal or a notarization.
    ///
    /// If the engine holds no record of the commitment and its record window
    /// admits `round`, it starts reconstructing the block from the shards its
    /// peers sent, including those buffered before this call. A later report of
    /// the same commitment only raises its round.
    ///
    /// `round` MUST come from a trusted consensus observation, and its epoch
    /// MUST be validated for `commitment`. The engine classifies the
    /// commitment's shards against that epoch's participant set, so an
    /// unvalidated epoch can misclassify shards from honest peers. The
    /// commitment's coding config MUST already have been validated against that
    /// participant set, as proposal verification does and as a notarization
    /// implies. The engine checks and decodes with the config the commitment
    /// claims, so under an unvalidated config a single shard could reconstruct
    /// a block.
    pub fn discovered(&self, commitment: Commitment<B, C, H>, round: Round) {
        let _ = self
            .sender
            .enqueue(Message::Discovered { commitment, round });
    }

    /// Request a reconstructed block by its [`Commitment`].
    pub async fn get(&self, commitment: Commitment<B, C, H>) -> Option<Arc<CodedBlock<B, C, H>>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetByCommitment {
            commitment,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Request a reconstructed block by its digest.
    pub async fn get_by_digest(&self, digest: B::Digest) -> Option<Arc<CodedBlock<B, C, H>>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetByDigest { digest, response });
        receiver.await.ok().flatten()
    }

    /// Subscribe to assigned shard verification for a commitment.
    ///
    /// For participants, this resolves once the shard for the local participant
    /// index has been verified. Reconstructing the full block from gossiped
    /// shards does not resolve this subscription: that
    /// block may still be used for later certification, but it is not enough
    /// to claim the participant received the shard it is expected to echo.
    ///
    /// For proposers, this resolves immediately after the locally built block
    /// is cached because they trivially have all shards.
    ///
    /// A non-participant has no assigned shard, so its subscription never
    /// resolves.
    pub fn subscribe_assigned_shard_verified(
        &self,
        commitment: Commitment<B, C, H>,
    ) -> oneshot::Receiver<()> {
        let (responder, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::SubscribeAssignedShardVerified {
                commitment,
                response: responder,
            });
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its [`Commitment`].
    pub fn subscribe(
        &self,
        commitment: Commitment<B, C, H>,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C, H>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByCommitment {
            commitment,
            response: responder,
        });
        receiver
    }

    /// Subscribe to the reconstruction of a [`CodedBlock`] by its digest.
    pub fn subscribe_by_digest(
        &self,
        digest: B::Digest,
    ) -> oneshot::Receiver<Arc<CodedBlock<B, C, H>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByDigest {
            digest,
            response: responder,
        });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::types::coding_config_for_participants,
            mocks::block::{EmptyBlock, encode_block},
        },
        types::{Epoch, Height, View},
    };
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        Committable, Digest as _, Sha256, sha256::Digest as Sha256Digest,
    };

    type B = EmptyBlock<Sha256>;
    type H = Sha256;
    type C = ReedSolomon<H>;
    type TestMessage = Message<B, C, H>;

    #[test]
    fn policy_drains_fifo() {
        let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 1);
        let block = encode_block::<B, C, H>(inner, coding_config_for_participants(4));
        let commitment = block.commitment();
        let round = Round::new(Epoch::zero(), View::new(1));

        let mut overflow = Pending::default();
        <TestMessage as Policy>::handle(&mut overflow, Message::Discovered { commitment, round });
        let (response, _get_rx) = oneshot::channel();
        <TestMessage as Policy>::handle(
            &mut overflow,
            Message::GetByCommitment {
                commitment,
                response,
            },
        );
        let mut drained = Vec::new();
        overflow.drain(|message| {
            drained.push(message);
            None
        });
        assert_eq!(drained.len(), 2);
        assert!(matches!(&drained[0], TestMessage::Discovered { .. }));
        assert!(matches!(&drained[1], TestMessage::GetByCommitment { .. }));
    }
}
