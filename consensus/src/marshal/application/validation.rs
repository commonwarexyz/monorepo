//! Shared validation helpers for marshal verification and reconstruction.
//!
//! This module centralizes pure invariant checks used by both standard and
//! coding marshal flows. Validators here return narrow error enums so call
//! sites can make explicit decisions about logging, voting, and recovery.

use crate::{
    marshal::coding::types::hash_context,
    types::{coding::Commitment, Epoch, Epocher, Height, Round},
    CertifiableBlock, Epochable,
};
use commonware_codec::{EncodeSize, Write};
use commonware_coding::Config as CodingConfig;
use commonware_cryptography::{Committable, Digest, Hasher};
use commonware_utils::sync::Mutex;
use std::sync::Arc;

/// Cache for the last block built during proposal, shared between the
/// proposer task and the broadcast path.
pub(crate) type LastBuilt<B> = Arc<Mutex<Option<(Round, B)>>>;

/// Validation failures for coding deferred verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodedBlockVerificationError {
    Commitment,
    ParentCommitment,
    Epoch,
    ParentDigest,
    Height,
    ContextHash,
    Context,
}

/// Validation failures for standard deferred verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StandardBlockVerificationError {
    ParentDigest,
    ExpectedParentDigest,
    Height,
}

/// Validation failures for coding proposal verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodedProposalValidationError {
    CodingConfig,
    ContextHash,
}

/// Validation failures for coded block reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconstructionValidationError<D: Digest> {
    BlockDigest,
    CodingConfig,
    ContextHash(D, D),
}

/// Returns true if the block is at an epoch boundary (last block in its epoch).
#[inline]
fn is_at_epoch_boundary<ES: Epocher>(epocher: &ES, block_height: Height, epoch: Epoch) -> bool {
    epocher.last(epoch).is_some_and(|last| last == block_height)
}

/// Returns true when a verify-time re-proposal is valid for the given epoch.
///
/// Re-proposals are only valid for the last block of the epoch.
#[inline]
pub(crate) fn is_valid_reproposal_at_verify<ES: Epocher>(
    epocher: &ES,
    block_height: Height,
    epoch: Epoch,
) -> bool {
    is_at_epoch_boundary(epocher, block_height, epoch)
}

/// Infers whether a certify-time block should be treated as a re-proposal.
///
/// During certification we may only have the block's embedded round, not the
/// consensus context used at verify time. We treat the block as a re-proposal
/// when it is an epoch-boundary block, the certify view is later than the
/// embedded view, and both rounds are in the same epoch.
#[inline]
pub(crate) fn is_inferred_reproposal_at_certify<ES: Epocher>(
    epocher: &ES,
    block_height: Height,
    embedded_round: Round,
    certify_round: Round,
) -> bool {
    is_at_epoch_boundary(epocher, block_height, embedded_round.epoch())
        && certify_round.view() > embedded_round.view()
        && certify_round.epoch() == embedded_round.epoch()
}

/// Returns true when `block_height` is mapped to `expected_epoch` by `epocher`.
///
/// If the height is not covered by the epoch strategy, this returns false.
#[inline]
pub(crate) fn is_block_in_expected_epoch<ES: Epocher>(
    epocher: &ES,
    block_height: Height,
    expected_epoch: Epoch,
) -> bool {
    epocher
        .containing(block_height)
        .is_some_and(|bounds| bounds.epoch() == expected_epoch)
}

/// Returns true when `block_height` is exactly the successor of `parent_height`.
#[inline]
pub(crate) fn has_contiguous_height(parent_height: Height, block_height: Height) -> bool {
    parent_height.next() == block_height
}

/// Consolidated validation for coding deferred verification.
pub(crate) fn validate_coded_block_for_verification<H, ES, B>(
    epocher: &ES,
    block: &B,
    parent: &B,
    context: &B::Context,
    commitment: Commitment,
    parent_commitment: Commitment,
) -> Result<(), CodedBlockVerificationError>
where
    H: Hasher,
    ES: Epocher,
    B: CertifiableBlock + Committable<Commitment = Commitment>,
    B::Context: Epochable + EncodeSize + Write + PartialEq,
{
    if block.commitment() != commitment {
        return Err(CodedBlockVerificationError::Commitment);
    }
    if parent.commitment() != parent_commitment {
        return Err(CodedBlockVerificationError::ParentCommitment);
    }
    if !is_block_in_expected_epoch(epocher, block.height(), context.epoch()) {
        return Err(CodedBlockVerificationError::Epoch);
    }
    if block.parent() != parent.digest() {
        return Err(CodedBlockVerificationError::ParentDigest);
    }
    if !has_contiguous_height(parent.height(), block.height()) {
        return Err(CodedBlockVerificationError::Height);
    }
    let block_context = block.context();
    if commitment.context::<H::Digest>() != hash_context::<H, _>(&block_context) {
        return Err(CodedBlockVerificationError::ContextHash);
    }
    if block_context != *context {
        return Err(CodedBlockVerificationError::Context);
    }
    Ok(())
}

/// Consolidated validation for standard deferred verification.
pub(crate) fn validate_standard_block_for_verification<B>(
    block: &B,
    parent: &B,
    parent_digest: B::Digest,
) -> Result<(), StandardBlockVerificationError>
where
    B: CertifiableBlock,
{
    if block.parent() != parent.digest() {
        return Err(StandardBlockVerificationError::ParentDigest);
    }
    if parent.digest() != parent_digest {
        return Err(StandardBlockVerificationError::ExpectedParentDigest);
    }
    if !has_contiguous_height(parent.height(), block.height()) {
        return Err(StandardBlockVerificationError::Height);
    }
    Ok(())
}

/// Consolidated validation for coding verify path.
///
/// If `context` is `None`, only coding-config validation is applied.
pub(crate) fn validate_coded_proposal<H: Hasher, C: EncodeSize + Write>(
    payload: Commitment,
    expected_config: CodingConfig,
    context: Option<&C>,
) -> Result<(), CodedProposalValidationError> {
    if payload.config() != expected_config {
        return Err(CodedProposalValidationError::CodingConfig);
    }
    if let Some(context) = context {
        if payload.context::<H::Digest>() != hash_context::<H, _>(context) {
            return Err(CodedProposalValidationError::ContextHash);
        }
    }
    Ok(())
}

/// Consolidated validation for reconstructed coded blocks.
pub(crate) fn validate_reconstruction<H, B>(
    block: &B,
    config: CodingConfig,
    commitment: Commitment,
) -> Result<(), ReconstructionValidationError<H::Digest>>
where
    H: Hasher,
    B: CertifiableBlock,
    B::Context: EncodeSize + Write,
{
    if block.digest() != commitment.block() {
        return Err(ReconstructionValidationError::BlockDigest);
    }
    if config != commitment.config() {
        return Err(ReconstructionValidationError::CodingConfig);
    }
    let commitment_context = commitment.context::<H::Digest>();
    let block_context = hash_context::<H, _>(&block.context());
    if commitment_context != block_context {
        return Err(ReconstructionValidationError::ContextHash(
            commitment_context,
            block_context,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::coding::types::coding_config_for_participants,
        types::{FixedEpocher, View},
    };
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_cryptography::{
        sha256::Digest as Sha256Digest, Committable, Digestible, Hasher, Sha256,
    };
    use commonware_utils::NZU64;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        digest: Sha256Digest,
        parent: Sha256Digest,
        height: Height,
        context: Round,
        commitment: Commitment,
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
            let commitment = Commitment::read(buf)?;
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
        type Commitment = Commitment;

        fn commitment(&self) -> Self::Commitment {
            self.commitment
        }
    }

    struct Fixture {
        epocher: FixedEpocher,
        block: TestBlock,
        parent: TestBlock,
        context: Round,
        commitment: Commitment,
        parent_commitment: Commitment,
        config: CodingConfig,
    }

    fn commitment_for(
        digest: Sha256Digest,
        context: Round,
        config: CodingConfig,
        root_label: &[u8],
    ) -> Commitment {
        Commitment::from((
            digest,
            Sha256::hash(root_label),
            hash_context::<Sha256, _>(&context),
            config,
        ))
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
    fn test_validate_coded_block_for_verification_commitment_error() {
        let fixture = baseline_fixture();
        let wrong = commitment_for(
            Sha256::hash(b"other_block"),
            fixture.context,
            fixture.config,
            b"other_root",
        );
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                wrong,
                fixture.parent_commitment,
            ),
            Err(CodedBlockVerificationError::Commitment)
        );
    }

    #[test]
    fn test_validate_coded_block_for_verification_parent_commitment_error() {
        let fixture = baseline_fixture();
        let wrong = commitment_for(
            Sha256::hash(b"other_parent"),
            fixture.parent.context,
            fixture.config,
            b"other_parent_root",
        );
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                wrong,
            ),
            Err(CodedBlockVerificationError::ParentCommitment)
        );
    }

    #[test]
    fn test_validate_coded_block_for_verification_epoch_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(1), View::new(7));
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &wrong_context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(CodedBlockVerificationError::Epoch)
        );
    }

    #[test]
    fn test_validate_coded_block_for_verification_parent_digest_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(CodedBlockVerificationError::ParentDigest)
        );
    }

    #[test]
    fn test_validate_coded_block_for_verification_height_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.height = Height::new(9);
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(CodedBlockVerificationError::Height)
        );
    }

    #[test]
    fn test_validate_coded_block_for_verification_context_hash_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        let wrong_context = Round::new(Epoch::new(0), View::new(9));
        let wrong_commitment =
            commitment_for(block.digest(), wrong_context, fixture.config, b"block_root");
        block.commitment = wrong_commitment;
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &block,
                &fixture.parent,
                &fixture.context,
                wrong_commitment,
                fixture.parent_commitment,
            ),
            Err(CodedBlockVerificationError::ContextHash)
        );
    }

    #[test]
    fn test_validate_coded_block_for_verification_context_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        assert_eq!(
            validate_coded_block_for_verification::<Sha256, _, _>(
                &fixture.epocher,
                &fixture.block,
                &fixture.parent,
                &wrong_context,
                fixture.commitment,
                fixture.parent_commitment,
            ),
            Err(CodedBlockVerificationError::Context)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_parent_digest_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_standard_block_for_verification(
                &block,
                &fixture.parent,
                fixture.parent.digest(),
            ),
            Err(StandardBlockVerificationError::ParentDigest)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_expected_parent_digest_error() {
        let fixture = baseline_fixture();
        assert_eq!(
            validate_standard_block_for_verification(
                &fixture.block,
                &fixture.parent,
                Sha256::hash(b"wrong_expected_parent"),
            ),
            Err(StandardBlockVerificationError::ExpectedParentDigest)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_height_error() {
        let fixture = baseline_fixture();
        let mut block = fixture.block.clone();
        block.height = Height::new(9);
        assert_eq!(
            validate_standard_block_for_verification(
                &block,
                &fixture.parent,
                fixture.parent.digest(),
            ),
            Err(StandardBlockVerificationError::Height)
        );
    }

    #[test]
    fn test_validate_coded_proposal_coding_config_error() {
        let fixture = baseline_fixture();
        let wrong = coding_config_for_participants(7);
        assert_eq!(
            validate_coded_proposal::<Sha256, _>(fixture.commitment, wrong, Some(&fixture.context)),
            Err(CodedProposalValidationError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_coded_proposal_context_hash_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        assert_eq!(
            validate_coded_proposal::<Sha256, _>(
                fixture.commitment,
                fixture.config,
                Some(&wrong_context)
            ),
            Err(CodedProposalValidationError::ContextHash)
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
            validate_reconstruction::<Sha256, _>(&fixture.block, fixture.config, wrong_commitment),
            Err(ReconstructionValidationError::BlockDigest)
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
            validate_reconstruction::<Sha256, _>(&fixture.block, fixture.config, wrong_commitment),
            Err(ReconstructionValidationError::CodingConfig)
        );
    }

    #[test]
    fn test_validate_reconstruction_context_hash_error() {
        let fixture = baseline_fixture();
        let wrong_context = Round::new(Epoch::new(0), View::new(8));
        let wrong_commitment = commitment_for(
            fixture.block.digest(),
            wrong_context,
            fixture.config,
            b"block_root",
        );
        assert_eq!(
            validate_reconstruction::<Sha256, _>(&fixture.block, fixture.config, wrong_commitment),
            Err(ReconstructionValidationError::ContextHash(
                wrong_commitment.context(),
                hash_context::<Sha256, _>(&fixture.block.context),
            ))
        );
    }
}
