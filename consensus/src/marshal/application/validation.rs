//! Shared and standard validation helpers for marshal verification.
//!
//! This module centralizes pure invariant checks shared across marshal flows,
//! plus standard-mode block verification checks.

use crate::{
    types::{Epoch, Epocher, Height, Round},
    Block,
};
use commonware_utils::sync::Mutex;
use std::sync::Arc;

/// Cache for the last block built during proposal, shared between the
/// proposer task and the broadcast path.
pub(crate) type LastBuilt<B> = Arc<Mutex<Option<(Round, B)>>>;

/// Validation failures for standard deferred verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StandardBlockVerificationError {
    ParentDigest,
    ExpectedParentDigest,
    Height,
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

/// Consolidated validation for standard deferred verification.
pub(crate) fn validate_standard_block_for_verification<B>(
    block: &B,
    parent: &B,
    parent_digest: B::Digest,
) -> Result<(), StandardBlockVerificationError>
where
    B: Block,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FixedEpocher, View};
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Digestible, Hasher, Sha256};
    use commonware_utils::NZU64;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        digest: Sha256Digest,
        parent: Sha256Digest,
        height: Height,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.digest.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.digest.encode_size() + self.parent.encode_size() + self.height.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let digest = Sha256Digest::read(buf)?;
            let parent = Sha256Digest::read(buf)?;
            let height = Height::read(buf)?;
            Ok(Self {
                digest,
                parent,
                height,
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

    fn baseline_blocks() -> (TestBlock, TestBlock) {
        let parent_digest = Sha256::hash(b"parent");
        let parent = TestBlock {
            digest: parent_digest,
            parent: Sha256::hash(b"grandparent"),
            height: Height::new(6),
        };
        let block = TestBlock {
            digest: Sha256::hash(b"block"),
            parent: parent_digest,
            height: Height::new(7),
        };
        (parent, block)
    }

    #[test]
    fn test_validate_standard_block_for_verification_ok() {
        let (parent, block) = baseline_blocks();
        assert_eq!(
            validate_standard_block_for_verification(&block, &parent, parent.digest()),
            Ok(())
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_parent_digest_error() {
        let (parent, mut block) = baseline_blocks();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_standard_block_for_verification(&block, &parent, parent.digest()),
            Err(StandardBlockVerificationError::ParentDigest)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_expected_parent_digest_error() {
        let (parent, block) = baseline_blocks();
        assert_eq!(
            validate_standard_block_for_verification(
                &block,
                &parent,
                Sha256::hash(b"wrong_expected_parent"),
            ),
            Err(StandardBlockVerificationError::ExpectedParentDigest)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_height_error() {
        let (parent, mut block) = baseline_blocks();
        block.height = Height::new(9);
        assert_eq!(
            validate_standard_block_for_verification(&block, &parent, parent.digest()),
            Err(StandardBlockVerificationError::Height)
        );
    }

    #[test]
    fn test_is_valid_reproposal_at_verify() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert!(is_valid_reproposal_at_verify(
            &epocher,
            Height::new(9),
            Epoch::new(0)
        ));
        assert!(!is_valid_reproposal_at_verify(
            &epocher,
            Height::new(8),
            Epoch::new(0)
        ));
    }

    #[test]
    fn test_is_inferred_reproposal_at_certify() {
        let epocher = FixedEpocher::new(NZU64!(10));
        let embedded = Round::new(Epoch::new(0), View::new(9));

        // Boundary block, later view, same epoch.
        assert!(is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(9),
            embedded,
            Round::new(Epoch::new(0), View::new(10)),
        ));

        // Same view is not inferred as re-proposal.
        assert!(!is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(9),
            embedded,
            Round::new(Epoch::new(0), View::new(9)),
        ));

        // Cross-epoch is not inferred as re-proposal.
        assert!(!is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(9),
            embedded,
            Round::new(Epoch::new(1), View::new(10)),
        ));
    }

    #[test]
    fn test_is_block_in_expected_epoch() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert!(is_block_in_expected_epoch(
            &epocher,
            Height::new(7),
            Epoch::new(0)
        ));
        assert!(!is_block_in_expected_epoch(
            &epocher,
            Height::new(7),
            Epoch::new(1)
        ));
    }
}
