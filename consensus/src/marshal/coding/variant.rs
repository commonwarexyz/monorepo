use crate::{
    marshal::{
        coding::{
            shards,
            types::{CodedBlock, StoredCodedBlock},
        },
        core::{Buffer, Variant},
    },
    types::{coding::Commitment, Round},
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
    type Commitment = Commitment;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        block.commitment()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        commitment.block()
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block.into_inner()
    }
}

impl<B, C, P> Buffer<Coding<B, C, P>> for shards::Mailbox<B, C, P>
where
    B: CertifiableBlock,
    C: CodingScheme,
    P: PublicKey,
{
    type CachedBlock = Arc<CodedBlock<B, C>>;

    async fn find_by_digest(
        &self,
        digest: <CodedBlock<B, C> as Digestible>::Digest,
    ) -> Option<Self::CachedBlock> {
        self.get_by_digest(digest).await
    }

    async fn find_by_commitment(&self, commitment: Commitment) -> Option<Self::CachedBlock> {
        self.get(commitment).await
    }

    async fn subscribe_by_digest(
        &self,
        digest: <CodedBlock<B, C> as Digestible>::Digest,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        self.subscribe_by_digest(digest).await
    }

    async fn subscribe_by_commitment(
        &self,
        commitment: Commitment,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        self.subscribe(commitment).await
    }

    async fn finalized(&self, commitment: Commitment) {
        self.prune(commitment).await;
    }

    async fn proposed(&self, round: Round, block: CodedBlock<B, C>) {
        self.proposed(round, block).await;
    }
}
