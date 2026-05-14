//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    marshal::core::{Buffer, Variant},
    types::Round,
    Block,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::Read;
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
    B: Block,
{
    type ApplicationBlock = B;
    type Block = B;
    type StoredBlock = B;
    type Commitment = <B as Digestible>::Digest;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        // Standard variant commitment is exactly the block digest.
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
        _expected: Self::Commitment,
    ) -> <Self::Block as Read>::Cfg {
        block_cfg.clone()
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block
    }
}

impl<B, K> Buffer<Standard<B>> for buffered::Mailbox<K, B>
where
    B: Block,
    K: PublicKey,
{
    type PublicKey = K;

    async fn find_by_digest(&self, digest: B::Digest) -> Option<B> {
        self.get(digest).await
    }

    async fn find_by_commitment(&self, commitment: B::Digest) -> Option<B> {
        self.find_by_digest(commitment).await
    }

    fn subscribe_by_digest(&self, digest: B::Digest) -> oneshot::Receiver<B> {
        let (tx, rx) = oneshot::channel();
        self.subscribe_prepared(digest, tx);
        rx
    }

    fn subscribe_by_commitment(&self, commitment: B::Digest) -> oneshot::Receiver<B> {
        self.subscribe_by_digest(commitment)
    }

    fn finalized(&self, _commitment: B::Digest) {
        // No cleanup needed in standard mode - the buffer handles its own pruning
    }

    fn send(&self, _round: Round, block: B, recipients: Recipients<K>) {
        Broadcaster::broadcast(self, recipients, block);
    }
}
