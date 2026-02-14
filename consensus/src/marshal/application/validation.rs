use crate::types::{Epoch, Epocher, Height, Round};

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
