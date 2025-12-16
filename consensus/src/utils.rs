//! Utility functions for consensus.

use crate::types::{Epoch, EpochConfig};

/// Returns the epoch the given height belongs to using the provided configuration.
///
/// Returns `None` if the height is not covered by any epoch range.
pub fn epoch_with_config(config: &EpochConfig, height: u64) -> Option<Epoch> {
    let _epoch_length = config.epoch_length_at(height)?;

    // Calculate cumulative epochs across ranges
    let mut cumulative_epoch = 0;

    for (range_start, range_epoch_length) in &config.ranges {
        if height >= *range_start {
            let next_range_start = config
                .ranges
                .iter()
                .find(|(start, _)| *start > *range_start)
                .map(|(start, _)| *start);

            if let Some(next_start) = next_range_start {
                if height < next_start {
                    let offset_in_range = height - range_start;
                    let epoch_offset = offset_in_range / range_epoch_length;
                    return Some(Epoch::new(cumulative_epoch + epoch_offset));
                } else {
                    let range_size = next_start - range_start;
                    let complete_epochs_in_range = range_size / range_epoch_length;
                    cumulative_epoch += complete_epochs_in_range;
                }
            } else {
                // This is the last range, height belongs here
                let offset_in_range = height - range_start;
                let epoch_offset = offset_in_range / range_epoch_length;
                return Some(Epoch::new(cumulative_epoch + epoch_offset));
            }
        }
    }

    None
}
