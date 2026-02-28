//! Standard variant implementation for Marshal.
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.

use crate::{
    marshal::core::{Buffer, ConsensusEngine, SimplexConsensus, Variant},
    types::Round,
    Block,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_cryptography::{certificate::Scheme as CertificateScheme, Digestible};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::marker::PhantomData;

/// The standard variant of Marshal, which broadcasts complete blocks.
///
/// This variant sends the entire block to all peers.
#[derive(Default, Clone, Copy)]
pub struct Standard<B: Block, C: ConsensusEngine<Commitment = <B as Digestible>::Digest>>(
    PhantomData<(B, C)>,
);

/// Standard marshal coupled to simplex consensus.
pub type StandardSimplex<B, S> = Standard<B, SimplexConsensus<S, <B as Digestible>::Digest>>;

commonware_macros::stability_scope!(ALPHA {
    use crate::marshal::core::MinimmitConsensus;

    /// Standard marshal coupled to minimmit consensus.
    pub type StandardMinimmit<B, S> = Standard<B, MinimmitConsensus<S, <B as Digestible>::Digest>>;
});

impl<B, C> Variant for Standard<B, C>
where
    B: Block,
    C: ConsensusEngine<Commitment = <B as Digestible>::Digest>,
{
    type Consensus = C;
    type ApplicationBlock = B;
    type Block = B;
    type StoredBlock = B;
    type Commitment = <B as Digestible>::Digest;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        block.digest()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        commitment
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        block.parent()
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block
    }
}

impl<B, C> Buffer<Standard<B, C>>
    for buffered::Mailbox<<<C as ConsensusEngine>::Scheme as CertificateScheme>::PublicKey, B>
where
    B: Block,
    C: ConsensusEngine<Commitment = <B as Digestible>::Digest>,
{
    type CachedBlock = B;

    async fn find_by_digest(&self, digest: B::Digest) -> Option<Self::CachedBlock> {
        self.get(digest).await
    }

    async fn find_by_commitment(&self, commitment: B::Digest) -> Option<Self::CachedBlock> {
        self.get(commitment).await
    }

    async fn subscribe_by_digest(&self, digest: B::Digest) -> oneshot::Receiver<Self::CachedBlock> {
        let (tx, rx) = oneshot::channel();
        self.subscribe_prepared(digest, tx).await;
        rx
    }

    async fn subscribe_by_commitment(
        &self,
        commitment: B::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        let (tx, rx) = oneshot::channel();
        self.subscribe_prepared(commitment, tx).await;
        rx
    }

    async fn finalized(&self, _commitment: B::Digest) {}

    async fn proposed(&self, _round: Round, block: B) {
        let _peers = Broadcaster::broadcast(self, Recipients::All, block).await;
    }
}
