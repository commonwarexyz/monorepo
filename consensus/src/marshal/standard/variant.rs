//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    Block,
    marshal::core::{Buffer, ExpectedCommitment, Retirement, Variant},
    types::Round,
};
use commonware_broadcast::buffered;
use commonware_codec::Read;
use commonware_cryptography::{Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::sync::Arc;

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: Block>(std::marker::PhantomData<B>);

impl<B> Variant for Standard<B>
where
    B: Block,
{
    type ApplicationBlock = B;
    type Block = Arc<B>;
    type StoredBlock = Arc<B>;
    type Commitment = <B as Digestible>::Digest;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        // Standard variant commitment is exactly the block digest.
        block.digest()
    }

    fn stored_commitment(block: &Self::StoredBlock) -> Self::Commitment {
        block.digest()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        // Trivial left-inverse: digest == commitment in this variant.
        commitment
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        // In standard mode, commitments are digests, so parent commitment is parent digest.
        block.parent()
    }

    fn block_cfg(
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        _expected: ExpectedCommitment<Self::Commitment>,
    ) -> <Self::Block as Read>::Cfg {
        block_cfg.clone()
    }

    fn into_shared(block: Self::Block) -> Arc<Self::ApplicationBlock> {
        block
    }

    fn from_application_block(
        block: Self::ApplicationBlock,
        _payload: Self::Commitment,
    ) -> Self::Block {
        Arc::new(block)
    }
}

impl<B, K> Buffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: Block,
    K: PublicKey,
{
    type PublicKey = K;

    async fn find_by_digest(&self, digest: B::Digest) -> Option<Arc<B>> {
        self.get(digest).await
    }

    async fn find_by_commitment(&self, commitment: B::Digest) -> Option<Arc<B>> {
        self.find_by_digest(commitment).await
    }

    fn subscribe_by_commitment(&self, commitment: B::Digest) -> Option<oneshot::Receiver<Arc<B>>> {
        Some(self.subscribe(commitment))
    }

    fn retire(&self, _update: Retirement<B::Digest>) {}

    fn send(&self, _round: Round, block: Arc<B>, recipients: Recipients<K>) {
        self.broadcast_shared(recipients, block);
    }
}
