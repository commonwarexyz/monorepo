//! Utility functions for the reshare example.

/// The number of blocks in an epoch.
///
/// Production systems should use a much larger value, as safety in the DKG/reshare depends on syncrhony.
/// All players must be online for a small duration during this window.
pub const BLOCKS_PER_EPOCH: u64 = 100;

/// Returns `Some(epoch)` if the height is the last block in the epoch, `None` otherwise.
pub fn is_last_block_in_epoch(height: u64) -> Option<u64> {
    // Genesis block is not in any epoch.
    if height == 0 {
        return None;
    }
    // Check if the height is the last block in the epoch.
    if !height.is_multiple_of(BLOCKS_PER_EPOCH) {
        return None;
    }

    // Return the epoch that the block belongs to.
    Some((height / BLOCKS_PER_EPOCH) - 1)
}

/// Returns `true` if the height is in the epoch, `false` otherwise.
pub fn height_in_epoch(height: u64, epoch: u64) -> bool {
    // Genesis block is not in any epoch.
    if height == 0 {
        return false;
    }
    let block_epoch = (height - 1) / BLOCKS_PER_EPOCH;
    block_epoch == epoch
}

/// Returns the last height in the epoch.
pub fn get_last_height(epoch: u64) -> u64 {
    epoch.checked_add(1).unwrap() * BLOCKS_PER_EPOCH
}
