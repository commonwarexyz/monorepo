//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    marshal::core::{BlockBuffer, Variant},
    Block,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_cryptography::{Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: Block>(std::marker::PhantomData<B>);

impl<B> Variant for Standard<B>
where
    B: Block<Commitment = <B as Digestible>::Digest>,
{
    type ApplicationBlock = B;
    type Block = B;
    type StoredBlock = B;
    type Commitment = B::Commitment;
    type Recipients = ();

    fn commitment_to_digest(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        commitment
    }

    fn into_application_block(block: Self::Block) -> Self::ApplicationBlock {
        block
    }
}

impl<B, K> BlockBuffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: Block<Commitment = <B as Digestible>::Digest>,
    K: PublicKey,
{
    type CachedBlock = B;

    async fn find_by_digest(&mut self, digest: B::Digest) -> Option<Self::CachedBlock> {
        // Try to get the block from the buffer
        self.get(None, digest, None).await.into_iter().next()
    }

    async fn find_by_commitment(&mut self, commitment: B::Digest) -> Option<Self::CachedBlock> {
        // In standard mode, commitment = digest
        self.find_by_digest(commitment).await
    }

    async fn subscribe_by_digest(
        &mut self,
        digest: B::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        let (tx, rx) = oneshot::channel();
        self.subscribe_prepared(None, digest, None, tx).await;
        rx
    }

    async fn subscribe_by_commitment(
        &mut self,
        commitment: B::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        // In standard mode, commitment = digest
        self.subscribe_by_digest(commitment).await
    }

    async fn finalized(&mut self, _commitment: B::Digest) {
        // No cleanup needed in standard mode - the buffer handles its own pruning
    }

    async fn broadcast(&mut self, block: B, _recipients: ()) {
        // Broadcast the block to all peers
        let _peers = Broadcaster::broadcast(self, Recipients::All, block).await;
    }
}
