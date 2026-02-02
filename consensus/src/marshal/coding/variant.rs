use crate::{
    marshal::{
        coding::{
            shards,
            types::{CodedBlock, DigestOrCommitment, StoredCodedBlock},
        },
        core::{BlockBuffer, Variant},
    },
    types::CodingCommitment,
    Block, Scheme,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Digestible, PublicKey};
use commonware_utils::channel::oneshot;
use std::sync::Arc;

/// The coding variant of Marshal, which uses erasure coding for block dissemination.
///
/// This variant distributes blocks as erasure-coded shards, allowing reconstruction
/// from a subset of shards. This reduces bandwidth requirements for block propagation.
#[derive(Default, Clone, Copy)]
pub struct Coding<B: Block, C: CodingScheme, P: PublicKey>(std::marker::PhantomData<(B, C, P)>);

impl<B: Block, C: CodingScheme, P: PublicKey> Variant for Coding<B, C, P> {
    type ApplicationBlock = B;
    type Block = CodedBlock<B, C>;
    type StoredBlock = StoredCodedBlock<B, C>;
    type Commitment = CodingCommitment;
    type LookupId = DigestOrCommitment<<B as Digestible>::Digest>;
    type Recipients = Vec<P>;

    fn commitment_to_digest(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        commitment.block_digest()
    }

    fn unwrap_working(block: Self::Block) -> Self::ApplicationBlock {
        block.into_inner()
    }

    fn wrap_stored(stored: Self::Block) -> Self::StoredBlock {
        StoredCodedBlock::new(stored)
    }

    fn unwrap_stored(stored: Self::StoredBlock) -> Self::Block {
        stored.into_coded_block()
    }

    fn lookup_from_commitment(commitment: Self::Commitment) -> Self::LookupId {
        DigestOrCommitment::Commitment(commitment)
    }

    fn lookup_from_digest(digest: <Self::Block as Digestible>::Digest) -> Self::LookupId {
        DigestOrCommitment::Digest(digest)
    }

    fn lookup_to_digest(lookup: Self::LookupId) -> <Self::Block as Digestible>::Digest {
        lookup.block_digest()
    }
}

impl<B, S, C, P> BlockBuffer<Coding<B, C, P>> for shards::Mailbox<B, S, C, P>
where
    B: Block,
    S: Scheme,
    C: CodingScheme,
    P: PublicKey,
{
    type CachedBlock = Arc<CodedBlock<B, C>>;

    async fn find(&mut self, lookup: DigestOrCommitment<B::Digest>) -> Option<Self::CachedBlock> {
        match lookup {
            DigestOrCommitment::Commitment(commitment) => {
                self.try_reconstruct(commitment).await.ok().flatten()
            }
            DigestOrCommitment::Digest(_digest) => {
                // With only a digest, we cannot reconstruct from shards because we don't have the coding commitment.
                // The caller should check cache/archives instead.
                None
            }
        }
    }

    async fn subscribe(
        &mut self,
        lookup: DigestOrCommitment<B::Digest>,
    ) -> oneshot::Receiver<Self::CachedBlock> {
        self.subscribe_block(lookup).await
    }

    async fn finalized(&mut self, commitment: CodingCommitment) {
        shards::Mailbox::finalized(self, commitment).await;
    }

    async fn broadcast(&mut self, block: CodedBlock<B, C>, recipients: Vec<P>) {
        self.proposed(block, recipients).await;
    }
}
