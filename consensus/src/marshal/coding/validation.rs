//! Coding-specific validation helpers for marshal verification and reconstruction.
//!
//! This module contains pure invariant checks for coding-mode proposal verification,
//! block verification, and reconstruction.

use crate::{
    marshal::application::validation::{has_contiguous_height, is_block_in_expected_epoch},
    types::{coding::Commitment, Epocher},
    CertifiableBlock, Epochable,
};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Committable, Digest, Digestible, Hasher};

/// Validation failures for coding proposal verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalError {
    CodingConfig,
    ContextDigest,
}

/// Validation failures for coding block verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockError {
    Commitment,
    ParentCommitment,
    Epoch,
    ParentDigest,
    Height,
    ContextDigest,
    Context,
}

/// Validation failures for coded block reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconstructionError<D: Digest> {
    BlockDigest,
    CodingConfig,
    ContextDigest(D, D),
}

/// Consolidated validation for coding proposal checks.
///
/// If `context_digest` is `None`, only coding-config validation is applied.
pub(crate) fn validate_proposal<B, C, H>(
    payload: Commitment<B, C, H>,
    expected_config: CodingConfig,
    context_digest: Option<H::Digest>,
) -> Result<(), ProposalError>
where
    B: Digestible,
    C: Scheme,
    H: Hasher,
{
    if payload.config() != expected_config {
        return Err(ProposalError::CodingConfig);
    }
    if context_digest.is_some_and(|context_digest| payload.context() != context_digest) {
        return Err(ProposalError::ContextDigest);
    }
    Ok(())
}

/// Consolidated validation for coding block verification.
pub(crate) fn validate_block<ES, B, CB, C, H>(
    epocher: &ES,
    block: &B,
    parent: &B,
    context: &B::Context,
    context_digest: H::Digest,
    commitment: Commitment<CB, C, H>,
    parent_commitment: Commitment<CB, C, H>,
) -> Result<(), BlockError>
where
    ES: Epocher,
    B: CertifiableBlock + Committable<Commitment = Commitment<CB, C, H>>,
    CB: Digestible<Digest = B::Digest>,
    C: Scheme,
    H: Hasher,
    B::Context: Epochable + PartialEq,
{
    if block.commitment() != commitment {
        return Err(BlockError::Commitment);
    }
    if parent.commitment() != parent_commitment {
        return Err(BlockError::ParentCommitment);
    }
    if !is_block_in_expected_epoch(epocher, block.height(), context.epoch()) {
        return Err(BlockError::Epoch);
    }
    if block.parent() != parent.digest() {
        return Err(BlockError::ParentDigest);
    }
    if !has_contiguous_height(parent.height(), block.height()) {
        return Err(BlockError::Height);
    }
    let block_context = block.context();
    if commitment.context() != context_digest {
        return Err(BlockError::ContextDigest);
    }
    if block_context != *context {
        return Err(BlockError::Context);
    }
    Ok(())
}

/// Consolidated validation for reconstructed coded blocks.
pub(crate) fn validate_reconstruction<B, C, H>(
    block: &B,
    config: CodingConfig,
    context_digest: H::Digest,
    commitment: Commitment<B, C, H>,
) -> Result<(), ReconstructionError<H::Digest>>
where
    B: CertifiableBlock,
    C: Scheme,
    H: Hasher,
{
    if block.digest() != commitment.block() {
        return Err(ReconstructionError::BlockDigest);
    }
    if config != commitment.config() {
        return Err(ReconstructionError::CodingConfig);
    }
    let commitment_context = commitment.context();
    if commitment_context != context_digest {
        return Err(ReconstructionError::ContextDigest(
            commitment_context,
            context_digest,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::coding::types::{coding_config_for_participants, hash_context},
        types::{Epoch, FixedEpocher, Height, Round, View},
    };
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        sha256::Digest as Sha256Digest, Committable, Digestible, Hasher, Sha256,
    };
    use commonware_utils::NZU64;

    type TestCommitment = Commitment<TestBlock, ReedSolomon<Sha256>, Sha256>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        digest: Sha256Digest,
        parent: Sha256Digest,
        height: Height,
        context: Round,
        commitment: TestCommitment,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.digest.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.context.write(buf);
            self.commitment.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.digest.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.context.encode_size()
                + self.commitment.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let digest = Sha256Digest::read(buf)?;
            let parent = Sha256Digest::read(buf)?;
            let height = Height::read(buf)?;
            let context = Round::read(buf)?;
            let commitment = TestCommitment::read(buf)?;
            Ok(Self {
                digest,
                parent,
                height,
                context,
                commitment,
            })
        }
    }

    impl Digestible for TestBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl crate::Heightable for TestBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl crate::Block for TestBlock {
        fn parent(&self) -> Self::Digest {
            self.parent
        }
    }

    impl crate::CertifiableBlock for TestBlock {
        type Context = Round;

        fn context(&self) -> Self::Context {
            self.context
        }
    }

    impl Committable for TestBlock {
        type Commitment = TestCommitment;

        fn commitment(&self) -> Self::Commitment {
            self.commitment
        }
    }

    struct Fixture {
        epocher: FixedEpocher,
        block: TestBlock,
        parent: TestBlock,
        context: Round,
        commitment: TestCommitment,
        parent_commitment: TestCommitment,
        config: CodingConfig,
    }

    fn commitment_for(
        digest: Sha256Digest,
        context: Round,
        config: CodingConfig,
        root_label: &[u8],
    ) -> TestCommitment {
        TestCommitment::from((
            digest,
            Sha256::hash(root_label),
            hash_context::<Sha256, _>(&context),
            config,
        ))
    }

    fn context_digest(context: &Round) -> Sha256Digest {
        hash_context::<Sha256, _>(context)
    }

    fn baseline_fixture() -> Fixture {
        let config = coding_config_for_participants(4);
        let epocher = FixedEpocher::new(NZU64!(10));

        let parent_context = Round::new(Epoch::new(0), View::new(6));
        let context = Round::new(Epoch::new(0), View::new(7));

        let parent_digest = Sha256::hash(b"parent");
        let digest = Sha256::hash(b"block");

        let parent_commitment =
            commitment_for(parent_digest, parent_context, config, b"parent_root");
        let commitment = commitment_for(digest, context, config, b"block_root");

        let parent = TestBlock {
            digest: parent_digest,
            parent: Sha256::hash(b"grandparent"),
            height: Height::new(6),
            context: parent_context,
            commitment: parent_commitment,
        };
        let block = TestBlock {
            digest,
            parent: parent_digest,
            height: Height::new(7),
            context,
            commitment,
        };

        Fixture {
            epocher,
            block,
            parent,
            context,
            commitment,
            parent_commitment,
            config,
        }
    }

    #[test]
    fn test_validate_block_ok() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                context_digest(&fixture.block.context),
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_proposal_ok() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_proposal(
                fixture.commitment,
                fixture.config,
                Some(context_digest(&fixture.context))
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_reconstruction_ok() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_reconstruction(
                &fixture.block,
                fixture.config,
                context_digest(&fixture.block.context),
                fixture.commitment
            ),
            Ok(())
        );
    }

    #[test]
    fn test_validate_block_commitment_error() {
        let fixture = baseline_fixture();
        let wrong = commitment_for(
            Sha256::hash(b"other_block"),
            fixture.context,
            fixture.config,
            b"other_root",
        );
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                context_digest(&fixture.block.context),
                wrong,
                fixture.parent_commitment,
            ),
            Err(BlockError::Commitment)
        );
    }

    #[test]
    fn test_validate_block_parent_commitment_error() {
        let fixture = baseline_fixture();
        let wrong = commitment_for(
            Sha256::hash(b"other_parent"),
            fixture.parent.context,
            fixture.config,
            b"other_parent_root",
        );
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                context_digest(&fixture.block.context),
                fixture.commitment,
                wrong,
            ),
            Err(BlockError::ParentCommitment)
        );
    }

    #[test]
    fn test_validate_block_epoch_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(1), View::new(7));
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &wrong_context,
                context_digest(&fixture.block.context),
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::Epoch)
        );
    }

    #[test]
    fn test_validate_block_parent_digest_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                context_digest(&block.context),
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::ParentDigest)
        );
    }

    #[test]
    fn test_validate_block_height_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.height = Height::new(9);
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                context_digest(&block.context),
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::Height)
        );
    }

    #[test]
    fn test_validate_block_context_digest_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        let wrong_context = Round::new(Epoch::new(0), View::new(9));
        let wrong_commitment =
            commitment_for(block.digest(), wrong_context, fixture.config, b"block_root");
        block.commitment = wrong_commitment;
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                context_digest(&block.context),
                wrong_commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::ContextDigest)
        );
    }

    #[test]
    fn test_validate_block_context_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        assert_eq!(
            validate_block(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &wrong_context,
                context_digest(&fixture.block.context),
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(BlockError::Context)
        );
    }

    #[test]
    fn test_validate_proposal_coding_config_error() {
        let fixture = baseline_fixture();
        let wrong = coding_config_for_participants(7);
        assert_eq!(
            validate_proposal(
                fixture.commitment,
                wrong,
                Some(context_digest(&fixture.context))
            ),
            Err(ProposalError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_proposal_context_digest_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        assert_eq!(
            validate_proposal(
                fixture.commitment,
                fixture.config,
                Some(context_digest(&wrong_context))
            ),
            Err(ProposalError::ContextDigest)
        );
    }

    #[test]
    fn test_validate_proposal_none_context_skips_context_digest_check() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        let payload_with_wrong_context = commitment_for(
            fixture.block.digest(),
            wrong_context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_proposal(payload_with_wrong_context, fixture.config, None),
            Ok(())
        );
    }

    #[test]
    fn test_validate_proposal_none_context_still_enforces_coding_config() {
        let fixture = baseline_fixture();
        let wrong = coding_config_for_participants(7);
        assert_eq!(
            validate_proposal(fixture.commitment, wrong, None),
            Err(ProposalError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_reconstruction_block_digest_error() {
        let fixture = baseline_fixture();
        let wrong_commitment = commitment_for(
            Sha256::hash(b"wrong_block_digest"),
            fixture.context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction(
                &fixture.block,
                fixture.config,
                context_digest(&fixture.block.context),
                wrong_commitment
            ),
            Err(ReconstructionError::BlockDigest)
        );
    }

    #[test]
    fn test_validate_reconstruction_coding_config_error() {
        let fixture = baseline_fixture();
        let wrong_config = coding_config_for_participants(7);
        let wrong_commitment = commitment_for(
            fixture.block.digest(),
            fixture.context,
            wrong_config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction(
                &fixture.block,
                fixture.config,
                context_digest(&fixture.block.context),
                wrong_commitment
            ),
            Err(ReconstructionError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_reconstruction_context_digest_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        let wrong_commitment = commitment_for(
            fixture.block.digest(),
            wrong_context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction(
                &fixture.block,
                fixture.config,
                context_digest(&fixture.block.context),
                wrong_commitment
            ),
            Err(ReconstructionError::ContextDigest(
                wrong_commitment.context(),
                context_digest(&fixture.block.context),
            ))
        );
    }
}
