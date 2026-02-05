use crate::{
    marshal::{
        coding::{
            shards,
            types::{CodedBlock, StoredCodedBlock},
        },
        core::{BlockBuffer, Variant},
    },
    types::CodingCommitment,
    CertifiableBlock,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_utils::channel::oneshot;
use std::sync::Arc;

/// The coding variant of Marshal, which uses erasure coding for block dissemination.
///
/// This variant distributes blocks as erasure-coded shards, allowing reconstruction
/// from a subset of shards. This reduces bandwidth requirements for block propagation.
#[derive(Default, Clone, Copy)]
pub struct Coding<B: CertifiableBlock, C: CodingScheme, P: PublicKey>(
    std::marker::PhantomData<(B, C, P)>,
);

impl<B: CertifiableBlock, C: CodingScheme, P: PublicKey> Variant for Coding<B, C, P> {
    type ApplicationBlock = B;
    type Block = CodedBlock<B, C>;
    type StoredBlock = StoredCodedBlock<B, C>;
    type Commitment = CodingCommitment;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        block.commitment()
    }

    fn commitment_to_digest(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        commitment.block_digest()
    }

    fn into_application_block(block: Self::Block) -> Self::ApplicationBlock {
        block.into_inner()
    }
}

impl<B, C, P> BlockBuffer<Coding<B, C, P>> for shards::Mailbox<B, C, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    P: PublicKey,
{
    type CachedBlock = Arc<CodedBlock<B, C>>;

    async fn find_by_digest(
        &mut self,
        _digest: <CodedBlock<B, C> as Digestible>::Digest,
    ) -> Option<Self::CachedBlock> {
        self.get_by_digest(_digest).await
    }

    async fn find_by_commitment(
        &mut self,
        commitment: CodingCommitment,
    ) -> Option<Self::CachedBlock> {
        self.get(commitment).await
    }

    async fn subscribe_by_digest(
        &mut self,
        digest: <CodedBlock<B, C> as Digestible>::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        self.subscribe_block_by_digest(digest).await
    }

    async fn subscribe_by_commitment(
        &mut self,
        commitment: CodingCommitment,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        self.subscribe_block(commitment).await
    }

    async fn finalized(&mut self, commitment: CodingCommitment) {
        self.durable(commitment).await;
    }

    async fn proposed(&mut self, block: CodedBlock<B, C>) {
        self.proposed(block).await;
    }
}
