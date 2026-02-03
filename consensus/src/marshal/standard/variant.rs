//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers without erasure coding.
//! This is simpler but uses more bandwidth than the coding variant.

use crate::{
    marshal::core::{BlockBuffer, Variant},
    Block,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers. It's simpler than
/// the coding variant but uses more bandwidth.
///
/// Since [`Block`] now requires [`Committable`],
/// the standard variant can use `B` directly without a wrapper type.
///
/// The `Standard` variant requires that `B::Commitment = B::Digest`, meaning
/// the block's commitment is simply its digest. This is the common case for
/// non-erasure-coded blocks.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: Block>(std::marker::PhantomData<B>);

impl<B> Variant for Standard<B>
where
    B: Block + Committable<Commitment = <B as Digestible>::Digest>,
{
    type ApplicationBlock = B;
    type Block = B;
    type StoredBlock = B;
    type Commitment = B::Commitment;
    type Recipients = ();

    fn commitment_to_digest(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        commitment
    }

    fn unwrap_working(block: Self::Block) -> Self::ApplicationBlock {
        block
    }

    fn wrap_stored(stored: Self::Block) -> Self::StoredBlock {
        stored
    }

    fn unwrap_stored(stored: Self::StoredBlock) -> Self::Block {
        stored
    }
}

impl<B, K> BlockBuffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: Block + Committable<Commitment = <B as Digestible>::Digest> + AsRef<B>,
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
