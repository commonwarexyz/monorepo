use crate::{
    marshal::{
        coding::{
            shards,
            types::{CodedBlock, StoredCodedBlock},
        },
        core::{Buffer, Variant},
    },
    simplex::types::Context,
    types::{coding::Commitment, Round},
    CertifiableBlock,
};
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{Committable, Digestible, Hasher, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;

/// The coding variant of Marshal, which uses erasure coding for block dissemination.
///
/// This variant distributes blocks as erasure-coded shards, allowing reconstruction
/// from a subset of shards. This reduces bandwidth requirements for block propagation.
#[derive(Default, Clone, Copy)]
pub struct Coding<B, C, H, P>(std::marker::PhantomData<(B, C, H, P)>)
where
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey;

impl<B, C, H, P> Variant for Coding<B, C, H, P>
where
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type ApplicationBlock = B;
    type Block = CodedBlock<B, C, H>;
    type StoredBlock = StoredCodedBlock<B, C, H>;
    type Commitment = Commitment;

    fn commitment(block: &Self::Block) -> Self::Commitment {
        // Commitment is deterministic from the coded block contents.
        block.commitment()
    }

    fn commitment_to_inner(commitment: Self::Commitment) -> <Self::Block as Digestible>::Digest {
        // The inner digest is embedded in the coding commitment.
        commitment.block()
    }

    fn parent_commitment(block: &Self::Block) -> Self::Commitment {
        // Parent commitment is embedded in the consensus context.
        block.context().parent.1
    }

    fn application_parent_commitment(block: &Self::ApplicationBlock) -> Self::Commitment {
        // Parent commitment is embedded in the consensus context.
        block.context().parent.1
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block.into_inner()
    }
}

impl<B, C, H, P> Buffer<Coding<B, C, H, P>> for shards::Mailbox<B, C, H, P>
where
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type PublicKey = P;

    async fn find_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> Option<CodedBlock<B, C, H>> {
        self.get_by_digest(digest).await
    }

    async fn find_by_commitment(&self, commitment: Commitment) -> Option<CodedBlock<B, C, H>> {
        self.get(commitment).await
    }

    async fn subscribe_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> oneshot::Receiver<CodedBlock<B, C, H>> {
        self.subscribe_by_digest(digest).await
    }

    async fn subscribe_by_commitment(
        &self,
        commitment: Commitment,
    ) -> oneshot::Receiver<CodedBlock<B, C, H>> {
        self.subscribe(commitment).await
    }

    async fn finalized(&self, commitment: Commitment) {
        self.prune(commitment).await;
    }

    async fn send(&self, round: Round, block: CodedBlock<B, C, H>, _recipients: Recipients<P>) {
        // Targeted forwarding is not supported by the coding variant.
        self.proposed(round, block).await;
    }
}
