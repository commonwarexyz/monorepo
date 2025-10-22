//! Utility functions for consensus.

use crate::types::Epoch;

/// Returns the epoch the given height belongs to.
///
/// Epochs are organized as follows:
///
/// ```txt
/// 0: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
/// 1: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
/// 2: [20, 21, 22, 23, 24, 25, 26, 27, 28, 29]
/// ...
/// ```
///
/// Epoch length is defined in number of blocks. Panics if `epoch_length` is
/// zero.
#[inline]
pub fn epoch(epoch_length: u64, height: u64) -> Epoch {
    assert!(epoch_length > 0);
    height / epoch_length
}

/// Returns the last block height for the given epoch.
///
/// Epoch length is defined in number of blocks. Panics if `epoch_length` is
/// zero or if overflow occurs.
#[inline]
pub fn last_block_in_epoch(epoch_length: u64, epoch: Epoch) -> u64 {
    assert!(epoch_length > 0);

    // (epoch + 1) * epoch_length - 1
    epoch
        .checked_add(1)
        .and_then(|next_epoch| next_epoch.checked_mul(epoch_length))
        .unwrap()
        - 1
}

/// Returns `Some(epoch)` if the height is the last block in the epoch, `None` otherwise.
///
/// Epoch length is defined in number of blocks. Panics if `epoch_length` is
/// zero.
#[inline]
pub fn is_last_block_in_epoch(epoch_length: u64, height: u64) -> Option<Epoch> {
    assert!(epoch_length > 0);

    // Check if the height is the last block in the epoch.
    if height % epoch_length != epoch_length - 1 {
        return None;
    }

    // Return the epoch that the block belongs to.
    Some(height / epoch_length)
}

/// Returns the position of `height` within its epoch (starting at zero).
///
/// Epoch length is defined in number of blocks. Panics if `epoch_length` is
/// zero.
#[inline]
pub fn relative_height_in_epoch(epoch_length: u64, height: u64) -> u64 {
    assert!(epoch_length > 0);
    height % epoch_length
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_returns_expected_epoch() {
        assert_eq!(epoch(10, 0), 0);
        assert_eq!(epoch(10, 9), 0);
        assert_eq!(epoch(10, 10), 1);
        assert_eq!(epoch(5, 42), 8);
    }

    #[test]
    fn last_block_in_epoch_returns_last_height() {
        assert_eq!(last_block_in_epoch(1, 0), 0);
        assert_eq!(last_block_in_epoch(10, 0), 9);
        assert_eq!(last_block_in_epoch(10, 1), 19);
        assert_eq!(last_block_in_epoch(5, 42), 214);
    }

    #[test]
    fn is_last_block_in_epoch_identifies_last_block() {
        assert_eq!(is_last_block_in_epoch(10, 9), Some(0));
        assert_eq!(is_last_block_in_epoch(10, 19), Some(1));
        assert_eq!(is_last_block_in_epoch(5, 214), Some(42));
    }

    #[test]
    fn is_last_block_in_epoch_returns_none_when_not_last_block() {
        assert_eq!(is_last_block_in_epoch(10, 0), None);
        assert_eq!(is_last_block_in_epoch(10, 5), None);
        assert_eq!(is_last_block_in_epoch(10, 18), None);
    }

    #[test]
    fn relative_height_in_epoch_returns_expected_offset() {
        assert_eq!(relative_height_in_epoch(10, 0), 0);
        assert_eq!(relative_height_in_epoch(10, 9), 9);
        assert_eq!(relative_height_in_epoch(10, 10), 0);
        assert_eq!(relative_height_in_epoch(5, 42), 2);
    }
}
