use crate::{
    marshal::{
        ancestry::BlockProvider,
        coding::{
            shards,
            types::{coding_config_for_participants, CodedBlock, CodedBlockCfg, StoredCodedBlock},
        },
        core::{Buffer, CommitmentFallback, Mailbox, Variant},
    },
    simplex::{scheme::Scheme as SimplexScheme, types::Context},
    types::{coding::Commitment, Round},
    CertifiableBlock,
};
use commonware_codec::Read;
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{certificate::Scheme, Committable, Digestible, Hasher, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::future::Future;

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

    fn check_payload<S>(scheme: &S, payload: Self::Commitment) -> bool
    where
        S: SimplexScheme<Self::Commitment>,
    {
        let n_participants = u16::try_from(scheme.participants().len())
            .expect("scheme must have at most 2^16-1 participants");
        payload.config() == coding_config_for_participants(n_participants)
    }

    fn block_cfg(
        block_cfg: &<Self::ApplicationBlock as Read>::Cfg,
        expected: Self::Commitment,
    ) -> <Self::Block as Read>::Cfg {
        CodedBlockCfg {
            inner: block_cfg.clone(),
            expected,
        }
    }

    fn into_inner(block: Self::Block) -> Self::ApplicationBlock {
        block.into_inner()
    }

    fn from_application_block(
        block: Self::ApplicationBlock,
        payload: Self::Commitment,
    ) -> Self::Block {
        CodedBlock::new_trusted(block, payload)
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

    fn subscribe_by_digest(
        &self,
        digest: <CodedBlock<B, C, H> as Digestible>::Digest,
    ) -> Option<oneshot::Receiver<CodedBlock<B, C, H>>> {
        Some(self.subscribe_by_digest(digest))
    }

    fn subscribe_by_commitment(
        &self,
        commitment: Commitment,
    ) -> Option<oneshot::Receiver<CodedBlock<B, C, H>>> {
        Some(self.subscribe(commitment))
    }

    fn finalized(&self, commitment: Commitment) {
        self.prune(commitment);
    }

    fn send(&self, round: Round, block: CodedBlock<B, C, H>, _recipients: Recipients<P>) {
        // Targeted forwarding is not supported by the coding variant.
        self.proposed(round, block);
    }
}

impl<S, B, C, H, P> BlockProvider for Mailbox<S, Coding<B, C, H, P>>
where
    S: Scheme,
    B: CertifiableBlock<Context = Context<Commitment, P>>,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    type Block = B;

    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Self::Block>> + Send + 'static {
        let receiver = block.height().previous().map(|parent_height| {
            self.subscribe_by_commitment(
                block.context().parent.1,
                CommitmentFallback::FetchByCommitment {
                    height: parent_height,
                },
            )
        });
        async move {
            let receiver = receiver?;
            receiver
                .await
                .ok()
                .map(<Coding<B, C, H, P> as Variant>::into_inner)
        }
    }
}
