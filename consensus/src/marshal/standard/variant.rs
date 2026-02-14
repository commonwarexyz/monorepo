//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    marshal::core::{BlockBuffer, Variant},
    types::Round,
    CertifiableBlock,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_cryptography::{Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: CertifiableBlock>(std::marker::PhantomData<B>);

impl<B> Variant for Standard<B>
where
    B: CertifiableBlock,
{
    type ApplicationBlock = B;
    type Block = B;
    type StoredBlock = B;
    type Commitment = <B as Digestible>::Digest;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        block.digest()
    }

    fn commitment_to_application(
        commitment: Self::Commitment,
    ) -> <Self::Block as Digestible>::Digest {
        commitment
    }

    fn into_application_block(block: Self::Block) -> Self::ApplicationBlock {
        block
    }
}

impl<B, K> BlockBuffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: CertifiableBlock,
    K: PublicKey,
{
    type CachedBlock = B;

    async fn find_by_digest(&mut self, digest: B::Digest) -> Option<Self::CachedBlock> {
        self.get(digest).await
    }

    async fn find_by_commitment(&mut self, commitment: B::Digest) -> Option<Self::CachedBlock> {
        self.find_by_digest(commitment).await
    }

    async fn subscribe_by_digest(
        &mut self,
        digest: B::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        let (tx, rx) = oneshot::channel();
        self.subscribe_prepared(digest, tx).await;
        rx
    }

    async fn subscribe_by_commitment(
        &mut self,
        commitment: B::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        self.subscribe_by_digest(commitment).await
    }

    async fn finalized(&mut self, _commitment: B::Digest) {
        // No cleanup needed in standard mode - the buffer handles its own pruning
    }

    async fn proposed(&mut self, _round: Round, block: B) {
        let _peers = Broadcaster::broadcast(self, Recipients::All, block).await;
    }
}
