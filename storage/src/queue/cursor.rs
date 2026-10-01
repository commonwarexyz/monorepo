//! Delivery and acknowledgement state shared by [super::Queue] and [super::Reader].

use super::Error;
use crate::{journal::contiguous::Contiguous, rmap::RMap};
use commonware_runtime::telemetry::metrics::{Gauge, GaugeExt as _};
use tracing::debug;

/// The next position to deliver and the set of acknowledged positions.
pub(super) struct Cursor {
    /// Position of the next item to dequeue.
    ///
    /// Note that `ack_up_to` can advance `ack_floor` past `read_pos`; in this case, `dequeue`
    /// skips the already-acked items.
    read_pos: u64,

    /// All items at positions < ack_floor are considered acknowledged.
    ack_floor: u64,

    /// Ranges of acknowledged items at positions >= ack_floor (in-memory only).
    ///
    /// When an item at position == ack_floor is acked, the floor advances
    /// and any contiguous acked items are consumed. Lost on restart.
    acked_above: RMap,

    /// Next item to dequeue.
    next: Gauge,

    /// Acknowledged items.
    floor: Gauge,
}

impl Cursor {
    /// Create a cursor that delivers from `start`, with every position below it acknowledged.
    pub(super) fn new(start: u64, next: Gauge, floor: Gauge) -> Self {
        let _ = next.try_set(start);
        let _ = floor.try_set(start);
        Self {
            read_pos: start,
            ack_floor: start,
            acked_above: RMap::new(),
            next,
            floor,
        }
    }

    /// Returns whether a specific position has been acknowledged.
    pub(super) fn is_acked(&self, position: u64) -> bool {
        position < self.ack_floor || self.acked_above.get(&position).is_some()
    }

    /// Read the next unacknowledged item from `items`, returning its position and value.
    /// Returns `None` when every item below `items.bounds().end` has been read or acknowledged.
    pub(super) async fn dequeue<C: Contiguous>(
        &mut self,
        items: &C,
    ) -> Result<Option<(u64, C::Item)>, Error> {
        let size = items.bounds().end;

        // Fast-forward above ack floor
        if self.read_pos < self.ack_floor {
            self.read_pos = self.ack_floor;
        }

        // Fast-forward past the ack range containing read_pos (if any).
        if let Some((_, end)) = self.acked_above.get(&self.read_pos) {
            self.read_pos = end.saturating_add(1);
        }

        // Record the next candidate position and stop when no unread item remains.
        let _ = self.next.try_set(self.read_pos);
        if self.read_pos >= size {
            return Ok(None);
        }

        // Advance delivery only after the item has been read successfully.
        let item = items.read(self.read_pos).await?;
        let pos = self.read_pos;
        self.read_pos += 1;
        let _ = self.next.try_set(self.read_pos);
        debug!(position = pos, "dequeued item");
        Ok(Some((pos, item)))
    }

    /// Mark the item at `position` as processed. If this creates a contiguous run from the ack
    /// floor, the floor advances.
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `position >= size`.
    pub(super) fn ack(&mut self, position: u64, size: u64) -> Result<(), Error> {
        if position >= size {
            return Err(Error::PositionOutOfRange(position, size));
        }

        // Already acked (below floor)
        if position < self.ack_floor {
            return Ok(());
        }

        // Already acked (above floor)
        if self.acked_above.get(&position).is_some() {
            return Ok(());
        }

        // Advance the floor only when its first unacknowledged item is acknowledged.
        if position == self.ack_floor {
            // Advance floor, consuming any contiguous acked items
            let next = position + 1;
            let final_floor = match self.acked_above.get(&next) {
                Some((_, end)) => end + 1,
                None => next,
            };
            self.acked_above.remove(next, final_floor - 1);
            self.ack_floor = final_floor;
            let _ = self.floor.try_set(self.ack_floor);
            debug!(floor = self.ack_floor, "advanced ack floor");
        } else {
            // Retain acknowledgements above the gap at the floor.
            self.acked_above.insert(position);
            debug!(position, "acked item above floor");
        }
        Ok(())
    }

    /// Acknowledge all items in `[ack_floor, up_to)` by advancing the floor directly.
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `up_to > size`.
    pub(super) fn ack_up_to(&mut self, up_to: u64, size: u64) -> Result<(), Error> {
        if up_to > size {
            return Err(Error::PositionOutOfRange(up_to, size));
        }

        // Nothing to do if up_to is at or below current floor
        if up_to <= self.ack_floor {
            return Ok(());
        }

        // Determine final floor: either up_to, or past any contiguous acked range at up_to
        let final_floor = match self.acked_above.get(&up_to) {
            Some((_, end)) => end + 1,
            None => up_to,
        };

        // Remove all entries covered by the new floor and advance
        self.acked_above.remove(self.ack_floor, final_floor - 1);
        self.ack_floor = final_floor;
        let _ = self.floor.try_set(self.ack_floor);
        debug!(floor = self.ack_floor, "batch acked up to");
        Ok(())
    }

    /// Returns the position of the next item [Self::dequeue] will check.
    pub(super) const fn read_position(&self) -> u64 {
        self.read_pos
    }

    /// Returns the position below which every item is acknowledged.
    pub(super) const fn ack_floor(&self) -> u64 {
        self.ack_floor
    }

    /// Returns whether every item below `size` has been acknowledged.
    pub(super) const fn is_empty(&self, size: u64) -> bool {
        // If acked_above is non-empty, there's a gap at ack_floor (otherwise floor
        // would have advanced). So all items acked implies ack_floor == size.
        self.ack_floor >= size
    }

    /// Reset the read position to the ack floor so [Self::dequeue] re-delivers every
    /// unacknowledged item.
    pub(super) fn reset(&mut self) {
        let old_pos = self.read_pos;
        self.read_pos = self.ack_floor;
        let _ = self.next.try_set(self.read_pos);
        debug!(
            old_read_pos = old_pos,
            new_read_pos = self.read_pos,
            "reset read position"
        );
    }

    /// Returns the number of acknowledged positions above the ack floor (test-only).
    #[cfg(test)]
    pub(super) fn acked_above_count(&self) -> usize {
        self.acked_above
            .iter()
            .map(|(&s, &e)| (e - s + 1) as usize)
            .sum()
    }
}
