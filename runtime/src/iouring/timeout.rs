//! Timeout wheel for io_uring user space operation deadlines.
//!
//! The implementation uses a single-level (non-hierarchical) hashed timing wheel with
//! power-of-two slots and bitsets for bounded scans.
//!
//! This wheel is intentionally optimized for the common runtime behavior where most
//! operations complete before their deadline and only a small fraction actually time out.
//!
//! Design notes:
//!
//! - Insert path is cheap (`push` into one bucket plus occupancy bit update).
//! - Expiry processing is lazy: bucket entries are drained by tick and callers decide
//!   whether an entry is still active or stale.
//! - Stale entries are expected and cheap to skip, which keeps bookkeeping overhead low
//!   when timeout expirations are rare.
//! - Expiry entries carry full waiter generations so callers can safely ignore stale
//!   entries after slot reuse. Each registration has at most one deadline.
//! - Buckets are drained in place, so inner `Vec` capacity is retained and reused across
//!   cycles to reduce allocations.
//! - Reusing an inactive bucket clears its stale entries without releasing capacity.
//!   This bounds retention across cycles even when the wheel never becomes idle.
//! - When no active deadlines remain, stale bucket entries are purged in bulk so
//!   occupancy metadata does not drift and cause spurious wakeups.
//!
//! Reference: <https://www.cs.columbia.edu/~nahum/w6998/papers/sosp87-timing-wheels.pdf>

use super::waiter::WaiterId;
use std::{
    mem,
    time::{Duration, Instant},
};

/// Monotonic timeout-wheel tick in the wheel's local time domain.
///
/// This is derived from `start` and `tick_nanos` inside [`TimeoutWheel::advance`]
/// and [`TimeoutWheel::checked_target_tick`]. It is not wall-clock time and should be
/// treated as an opaque counter.
pub type Tick = u64;

/// Single-level (non-hierarchical) hashed timing wheel used for deadline tracking.
pub struct TimeoutWheel {
    /// Bitmask used to map ticks to slot indices.
    slot_mask: usize,
    /// Fixed ring of wheel slots, each slot stores a bucket of timeout entries.
    ///
    /// A slot is chosen by `tick & slot_mask`. Multiple target ticks can map to
    /// the same slot over time, and each slot bucket may contain multiple entries.
    buckets: Vec<Vec<WaiterId>>,
    /// Occupancy bitset for buckets that contain any entries (active or stale).
    occupied: Vec<u64>,
    /// Number of occupied bucket slots currently represented in `occupied`.
    occupied_slots: usize,
    /// Count of active deadlines by slot index.
    active_counts: Vec<u32>,
    /// Occupancy bitset for slots with at least one active deadline.
    active_occupied: Vec<u64>,
    /// Last tick processed by `advance`.
    current_tick: Tick,
    /// Earliest known active target tick (`Tick::MAX` when empty).
    ///
    /// This may remain temporarily stale until callers process expired entries
    /// and call `remove`.
    min_scheduled_tick: Tick,
    /// Count of currently active deadline-tracked entries.
    active_deadlines: usize,
    /// Maximum remaining operation timeout accepted during deadline registration.
    max_timeout_nanos: u64,
    /// Tick size in nanoseconds.
    tick_nanos: u64,
    /// Epoch used to convert between absolute instants and wheel ticks.
    start: Instant,
}

impl TimeoutWheel {
    /// Largest supported operation timeout, using 365 days per year.
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);

    /// Maximum number of buckets in the single-level wheel.
    const MAX_SLOTS: usize = 1_048_576;

    /// Number of bits per word in the occupancy bitsets.
    const WORD_BITS: usize = u64::BITS as usize;

    /// Convert a duration to nanoseconds, saturating at `u64::MAX`.
    ///
    /// We keep wheel arithmetic in `u64` nanoseconds for fast integer tick math.
    /// This intentionally prefers safety over precision for very large values.
    /// Callers that require bounded precision should clamp before conversion.
    const fn duration_to_nanos_saturating(duration: Duration) -> u64 {
        duration
            .as_secs()
            .saturating_mul(1_000_000_000)
            .saturating_add(duration.subsec_nanos() as u64)
    }

    /// Validate a wheel layout without allocating its buckets.
    ///
    /// Returns the power-of-two slot count. Both durations must be nonzero,
    /// the timeout cannot exceed [`Self::MAX_TIMEOUT`], and the layout cannot
    /// exceed [`Self::MAX_SLOTS`]. Duration conversion and size rounding are
    /// checked before any memory is allocated.
    pub fn validate_layout(max_timeout: Duration, tick: Duration) -> Result<usize, &'static str> {
        if max_timeout.is_zero() || max_timeout > Self::MAX_TIMEOUT {
            return Err("timeout wheel horizon must be nonzero and at most 30 years");
        }
        let tick_nanos = u64::try_from(tick.as_nanos())
            .map_err(|_| "timeout wheel tick nanoseconds overflow")?;
        if tick_nanos == 0 {
            return Err("timeout wheel tick must be non-zero");
        }
        let max_timeout_nanos = u64::try_from(max_timeout.as_nanos())
            .map_err(|_| "timeout wheel horizon nanoseconds overflow")?;

        // A deadline rounds upward while the current tick rounds downward.
        // Reserve one tick for this alignment and another so a valid target
        // always satisfies the strict span bound used by `schedule`.
        let required_ticks = max_timeout_nanos
            .div_ceil(tick_nanos)
            .checked_add(2)
            .ok_or("timeout wheel size overflow")?;
        let slots = usize::try_from(required_ticks)
            .map_err(|_| "timeout wheel size overflow")?
            .checked_next_power_of_two()
            .ok_or("timeout wheel size overflow")?;
        if slots > Self::MAX_SLOTS {
            return Err("timeout wheel exceeds 1048576 slots");
        }
        Ok(slots)
    }

    /// Create a timeout wheel.
    ///
    /// - `tick` defines the wheel granularity.
    /// - `max_timeout` bounds remaining operation time during registration.
    /// - `start` is the epoch used to convert `Instant` values into wheel ticks.
    ///
    /// The slot count is rounded up to a power of two for fast masking.
    ///
    /// Panics if [`Self::validate_layout`] rejects the configuration.
    pub fn new(max_timeout: Duration, tick: Duration, start: Instant) -> Self {
        let slots = Self::validate_layout(max_timeout, tick).expect("invalid timeout wheel layout");
        let tick_nanos = u64::try_from(tick.as_nanos()).expect("timeout wheel tick overflow");
        let buckets = vec![Vec::new(); slots];

        Self {
            slot_mask: slots - 1,
            buckets,
            occupied: vec![0; slots.div_ceil(Self::WORD_BITS)],
            occupied_slots: 0,
            active_counts: vec![0; slots],
            active_occupied: vec![0; slots.div_ceil(Self::WORD_BITS)],
            current_tick: 0,
            min_scheduled_tick: Tick::MAX,
            active_deadlines: 0,
            max_timeout_nanos: Self::duration_to_nanos_saturating(max_timeout),
            tick_nanos,
            start,
        }
    }

    /// Compute a target tick after advancing the wheel with `now`.
    ///
    /// Returns `Ok(None)` when the exact deadline has elapsed. Future deadlines
    /// must fit the configured horizon relative to the same service-time sample
    /// and the slot span relative to the refreshed tick. Unsupported deadlines
    /// are rejected rather than shortened. This method does not read the clock.
    pub fn checked_target_tick(
        &self,
        deadline: Instant,
        now: Instant,
    ) -> Result<Option<Tick>, &'static str> {
        if deadline <= now {
            return Ok(None);
        }
        if deadline.duration_since(now) > Duration::from_nanos(self.max_timeout_nanos) {
            return Err("operation deadline exceeds timeout wheel horizon");
        }
        let deadline_nanos = u64::try_from(deadline.duration_since(self.start).as_nanos())
            .map_err(|_| "operation deadline nanoseconds overflow")?;
        let target_tick = deadline_nanos.div_ceil(self.tick_nanos);
        target_tick
            .checked_sub(self.current_tick)
            .filter(|span| *span > 0 && *span < self.buckets.len() as Tick)
            .ok_or("operation deadline exceeds refreshed timeout wheel span")?;
        Ok(Some(target_tick))
    }

    /// Schedule `id` at `target_tick`.
    ///
    /// Call [`Self::advance`] with the current service time and remove its active
    /// expiries before scheduling new deadlines. This keeps live ticks within
    /// one revolution so distinct ticks cannot share a bucket.
    ///
    /// Invariants:
    /// - `target_tick` must be in the future relative to `current_tick`.
    /// - `target_tick` must be within wheel horizon (`target_tick - current_tick < slots`).
    /// - Callers must eventually pair this with exactly one `remove`.
    pub fn schedule(&mut self, id: WaiterId, target_tick: Tick) {
        let delta = target_tick.wrapping_sub(self.current_tick);
        assert!(delta > 0, "target_tick must be in the future");
        assert!(
            delta < self.buckets.len() as Tick,
            "target_tick exceeds timeout wheel horizon"
        );

        let slot = self.slot_index(target_tick);
        if self.buckets[slot].is_empty() {
            // Occupied bitset tracks non-empty buckets (active or stale) for bounded scans.
            assert_eq!(
                self.occupied[slot / Self::WORD_BITS] & (1u64 << (slot % Self::WORD_BITS)),
                0
            );
            self.occupied[slot / Self::WORD_BITS] |= 1u64 << (slot % Self::WORD_BITS);
            self.occupied_slots += 1;
        }

        // Every candidate in an inactive bucket is stale. Clear them before
        // reuse so early completions cannot accumulate across wheel revolutions.
        if self.active_counts[slot] == 0 {
            self.buckets[slot].clear();
        }

        // Append timeout candidate, stale entries are filtered by caller on drain.
        self.buckets[slot].push(id);
        self.active_deadlines += 1;

        // Track active deadlines per slot to support fast min recomputation.
        let new_count = self.active_counts[slot]
            .checked_add(1)
            .expect("active deadline count overflow");
        self.active_counts[slot] = new_count;

        if new_count == 1 {
            // This slot transitioned from no active deadlines to active.
            self.active_occupied[slot / Self::WORD_BITS] |= 1u64 << (slot % Self::WORD_BITS);
        }

        // Set lower bound for the next deadline query.
        self.min_scheduled_tick = self.min_scheduled_tick.min(target_tick);
    }

    /// Remove one active deadline tracked at `target_tick`.
    ///
    /// Call this exactly once when a scheduled waiter leaves active timeout tracking
    /// (for example: operation completed, or timeout cancellation was requested for
    /// a still-active waiter).
    ///
    /// Do not call this for stale drained entries that are no longer active.
    pub fn remove(&mut self, target_tick: Tick) {
        assert!(
            self.active_deadlines > 0,
            "active_deadlines underflow in remove"
        );
        self.active_deadlines -= 1;

        let slot = self.slot_index(target_tick);
        let new_count = self.active_counts[slot]
            .checked_sub(1)
            .expect("active deadline count missing in remove");
        self.active_counts[slot] = new_count;

        if new_count == 0 {
            // Slot no longer contains active deadlines.
            self.active_occupied[slot / Self::WORD_BITS] &= !(1u64 << (slot % Self::WORD_BITS));
        }

        if self.active_deadlines == 0 {
            // No active deadlines remain.
            self.min_scheduled_tick = Tick::MAX;
            return;
        }

        if target_tick != self.min_scheduled_tick {
            // Removed tick was not the tracked minimum, so minimum is unchanged.
            return;
        }

        // The wheel horizon guarantees `target_tick - current_tick < slots`, so two
        // distinct active ticks cannot alias to the same slot at once. If this slot
        // still has active entries, they must be for the same `target_tick`, and the
        // minimum tick is unchanged.
        if self.active_counts[slot] != 0 {
            return;
        }

        // The previous minimum was fully removed, find the next active slot.
        self.min_scheduled_tick = self.compute_min_scheduled_tick();
    }

    /// Advance wheel time to `now` and drain any buckets that became due.
    ///
    /// Returns `Some(entries)` when one or more buckets are drained.
    /// Returns `None` when no buckets are drained.
    ///
    /// Returned entries are timeout candidates and may include stale waiter ids.
    /// Callers should call [`Self::remove`] only for entries that were still active
    /// at cancellation time. Draining does not change their active counts. Remove
    /// all active expiries before scheduling again or querying the next deadline.
    ///
    /// When no active deadlines exist, this still advances `current_tick` and may
    /// purge stale occupied buckets.
    pub fn advance(&mut self, now: Instant) -> Option<Vec<WaiterId>> {
        let elapsed = now.saturating_duration_since(self.start);
        let now_tick = Self::duration_to_nanos_saturating(elapsed) / self.tick_nanos;

        if now_tick <= self.current_tick {
            // Time did not advance in wheel domain.
            return None;
        }

        let previous_tick = mem::replace(&mut self.current_tick, now_tick);

        if self.active_deadlines == 0 {
            // Idle fast path: when stale occupied slots exist (`occupied_slots != 0`),
            // purge them now.
            if self.occupied_slots != 0 {
                self.drain_occupied_buckets(Vec::clear);
            }
            return None;
        }

        if self.current_tick < self.min_scheduled_tick {
            // Earliest active deadline is still in the future.
            return None;
        }

        let mut expired = Vec::new();
        let elapsed = self.current_tick - previous_tick;
        if elapsed >= self.buckets.len() as Tick {
            // If we advanced by at least one full revolution, all buckets in
            // the wheel domain are expired and can be drained in one pass.
            self.drain_occupied_buckets(|bucket| expired.append(bucket));
            return Some(expired);
        }

        let start_slot = self.slot_index(previous_tick + 1);
        let end_slot = self.slot_index(self.current_tick);

        if start_slot <= end_slot {
            // Range does not wrap around the ring boundary.
            self.drain_occupied_range(start_slot, end_slot + 1, &mut expired);
        } else {
            // Range wraps around, drain tail then head.
            self.drain_occupied_range(start_slot, self.buckets.len(), &mut expired);
            self.drain_occupied_range(0, end_slot + 1, &mut expired);
        }

        if expired.is_empty() {
            None
        } else {
            Some(expired)
        }
    }

    /// Return the absolute instant of the next active deadline tick.
    ///
    /// Deriving this from the wheel epoch avoids extending the wait when user
    /// callbacks run between deadline service and parking. Remove active expiries
    /// before querying it.
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.min_scheduled_tick == Tick::MAX {
            return None;
        }
        Some(self.instant_at_tick(self.min_scheduled_tick))
    }

    /// Convert a target tick to an absolute instant without narrowing its
    /// nanosecond offset before splitting it into seconds and nanoseconds.
    fn instant_at_tick(&self, tick: Tick) -> Instant {
        let nanos = u128::from(tick) * u128::from(self.tick_nanos);
        let duration = Duration::new(
            u64::try_from(nanos / 1_000_000_000).expect("timeout wheel deadline seconds overflow"),
            (nanos % 1_000_000_000) as u32,
        );
        self.start
            .checked_add(duration)
            .expect("timeout wheel deadline overflow")
    }

    /// Map an absolute tick to its wheel slot index.
    #[inline]
    const fn slot_index(&self, tick: Tick) -> usize {
        (tick as usize) & self.slot_mask
    }

    /// Drain every currently occupied bucket.
    ///
    /// For each set slot in the occupied bitset, invokes `drain` with that slot's
    /// bucket and clears occupancy metadata.
    fn drain_occupied_buckets(&mut self, mut drain: impl FnMut(&mut Vec<WaiterId>)) {
        for word_index in 0..self.occupied.len() {
            let mut word = self.occupied[word_index];
            if word == 0 {
                // No occupied slots in this block.
                continue;
            }

            // Clear once per word, then iterate set bits from local copy.
            self.occupied[word_index] = 0;
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let slot = word_index * Self::WORD_BITS + bit;

                assert!(
                    slot < self.buckets.len(),
                    "occupied bitset contains out-of-range slot index"
                );
                drain(&mut self.buckets[slot]);

                // Clear lowest set bit.
                word &= word - 1;
            }
        }

        self.occupied_slots = 0;
    }

    /// Drain occupied slots in `[start, end)` in one bitset pass.
    ///
    /// This reads occupancy at word granularity, clears occupied bits for the
    /// drained range, and appends drained buckets into `expired`.
    fn drain_occupied_range(&mut self, start: usize, end: usize, expired: &mut Vec<WaiterId>) {
        if start >= end {
            return;
        }

        // Iterate the minimal set of bitset words covering [start, end).
        let start_word = start / Self::WORD_BITS;
        let end_word = (end - 1) / Self::WORD_BITS;
        for word_index in start_word..=end_word {
            let word_start = word_index * Self::WORD_BITS;
            let range_start = start.max(word_start);
            let range_end = end.min(word_start + Self::WORD_BITS);

            // Build a per-word mask for the [range_start, range_end) slice.
            let lo = range_start - word_start;
            let hi = range_end - word_start;
            let mut mask = u64::MAX << lo;
            if hi < Self::WORD_BITS {
                // Keep only bits below `hi` when the range ends mid-word.
                mask &= (1u64 << hi) - 1;
            }

            // Consider only occupied slots that are also in the masked sub-range.
            let mut word = self.occupied[word_index] & mask;
            if word == 0 {
                continue;
            }

            // Clear drained occupancy bits in one write for this word.
            self.occupied[word_index] &= !word;
            self.occupied_slots -= word.count_ones() as usize;
            while word != 0 {
                // Drain each set slot in this word.
                let bit = word.trailing_zeros() as usize;
                let slot = word_start + bit;
                let bucket = &mut self.buckets[slot];

                assert!(
                    !bucket.is_empty(),
                    "occupied bit set for empty timeout bucket"
                );
                expired.append(bucket);

                // Clear lowest set bit.
                word &= word - 1;
            }
        }
    }

    /// Compute the earliest active target tick from current wheel state.
    ///
    /// Returns `Tick::MAX` when no active slots are present.
    fn compute_min_scheduled_tick(&self) -> Tick {
        let start_slot = self.slot_index(self.current_tick.wrapping_add(1));
        let bits = &self.active_occupied;
        let slots = self.buckets.len();

        // Scan a bitset range [start, end) and return the first set slot index.
        let scan_set_range = |start: usize, end: usize| -> Option<usize> {
            if start >= end {
                return None;
            }

            let mut bit = start;
            while bit < end {
                let word_index = bit / Self::WORD_BITS;
                let bit_in_word = bit % Self::WORD_BITS;
                let mut word = bits[word_index];

                // Ignore bits below current scan cursor.
                word &= u64::MAX << bit_in_word;

                let word_end = ((word_index + 1) * Self::WORD_BITS).min(end);
                let bits_in_range = word_end - (word_index * Self::WORD_BITS);
                if bits_in_range < Self::WORD_BITS {
                    // Ignore bits beyond range end in final partial word.
                    word &= (1u64 << bits_in_range) - 1;
                }

                if word != 0 {
                    // Found the first set slot in this word.
                    let trailing = word.trailing_zeros() as usize;
                    return Some(word_index * Self::WORD_BITS + trailing);
                }

                // Advance to next word boundary.
                bit = (word_index + 1) * Self::WORD_BITS;
            }

            None
        };

        // Search from `start_slot` to end, then wrap to beginning once.
        let Some(next_slot) =
            scan_set_range(start_slot, slots).or_else(|| scan_set_range(0, start_slot))
        else {
            return Tick::MAX;
        };

        // Convert slot distance (from next tick onward) back to absolute tick.
        let delta_slots = if next_slot >= start_slot {
            next_slot - start_slot + 1
        } else {
            self.buckets.len() - start_slot + next_slot + 1
        };

        self.current_tick.saturating_add(delta_slots as Tick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::waiter::tests::waiter_id;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Granularity shared by the wheel fixtures.
    const TICK: Duration = Duration::from_millis(5);

    /// Construct a wheel with the test granularity.
    fn wheel(max_timeout: Duration) -> TimeoutWheel {
        TimeoutWheel::new(max_timeout, TICK, Instant::now())
    }

    /// Convert a fixture tick to its absolute instant.
    fn now_for_tick(wheel: &TimeoutWheel, tick: Tick) -> Instant {
        wheel.start + Duration::from_nanos(tick.saturating_mul(wheel.tick_nanos))
    }

    /// Advance to a fixture tick, returning any drained candidates.
    fn advance(wheel: &mut TimeoutWheel, tick: Tick) -> Vec<WaiterId> {
        wheel.advance(now_for_tick(wheel, tick)).unwrap_or_default()
    }

    #[test]
    fn test_layout_rounding_and_limits() {
        // Alignment and the strict span bound need two guard ticks before rounding.
        for (horizon, slots) in [
            (Duration::from_nanos(1), 4),
            (Duration::from_millis(15), 8),
            (Duration::from_secs(60), 16_384),
        ] {
            assert_eq!(TimeoutWheel::validate_layout(horizon, TICK), Ok(slots));
            assert_eq!(wheel(horizon).buckets.len(), slots);
        }

        // Validate the largest supported layouts without allocating their buckets.
        assert!(
            TimeoutWheel::validate_layout(TimeoutWheel::MAX_TIMEOUT, Duration::from_secs(3600))
                .is_ok()
        );
        assert_eq!(
            TimeoutWheel::validate_layout(
                Duration::from_nanos(TimeoutWheel::MAX_SLOTS as u64 - 2),
                Duration::from_nanos(1),
            ),
            Ok(TimeoutWheel::MAX_SLOTS)
        );
    }

    #[test]
    fn test_invalid_layouts() {
        let start = Instant::now();
        for (horizon, tick) in [
            (Duration::ZERO, TICK),
            (TICK, Duration::ZERO),
            (TICK, Duration::MAX),
            (Duration::MAX, TICK),
            (
                TimeoutWheel::MAX_TIMEOUT + Duration::from_nanos(1),
                Duration::from_secs(3600),
            ),
            (
                Duration::from_nanos(TimeoutWheel::MAX_SLOTS as u64 - 1),
                Duration::from_nanos(1),
            ),
        ] {
            // Configuration validation and construction must reject the same inputs.
            assert!(TimeoutWheel::validate_layout(horizon, tick).is_err());
            assert!(catch_unwind(|| TimeoutWheel::new(horizon, tick, start)).is_err());
        }
    }

    #[test]
    fn test_deadline_horizon_and_alignment() {
        let horizon = Duration::from_millis(15);
        let mut wheel = wheel(horizon);
        let now = wheel.start + Duration::from_millis(1);
        assert!(wheel.advance(now).is_none());

        // Exact expiry is checked before rounding, even within the current tick.
        assert_eq!(wheel.checked_target_tick(wheel.start, now), Ok(None));
        assert_eq!(wheel.checked_target_tick(now, now), Ok(None));
        assert_eq!(
            wheel.checked_target_tick(now + Duration::from_nanos(1), now),
            Ok(Some(1))
        );

        // A full-horizon deadline rounds up to tick four. Four slots would alias
        // the current tick, so this alignment requires an eight-slot wheel.
        assert_eq!(wheel.buckets.len(), 8);
        assert_eq!(wheel.checked_target_tick(now + horizon, now), Ok(Some(4)));
        assert!(
            wheel
                .checked_target_tick(now + horizon + Duration::from_nanos(1), now)
                .is_err()
        );

        wheel.schedule(waiter_id(0, 0), 4);
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 4)));
        assert!(advance(&mut wheel, 3).is_empty());
        assert_eq!(advance(&mut wheel, 4), vec![waiter_id(0, 0)]);
        wheel.remove(4);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_deadline_registration_requires_refreshed_time() {
        let horizon = Duration::from_millis(15);
        let mut wheel = wheel(horizon);
        let now = wheel.start + Duration::from_secs(60) + Duration::from_millis(1);

        // A long idle period must be reflected before accepting new deadlines.
        assert!(wheel.checked_target_tick(now + horizon, now).is_err());
        assert!(wheel.advance(now).is_none());
        let target = wheel
            .checked_target_tick(now + horizon, now)
            .unwrap()
            .unwrap();
        assert_eq!(target, 12_004);
        wheel.schedule(waiter_id(0, 0), target);

        // Service time can move forward without shifting the absolute parking deadline.
        let deadline = wheel.start + Duration::from_millis(60_020);
        assert_eq!(wheel.next_deadline(), Some(deadline));
        assert!(wheel.advance(now + Duration::from_millis(6)).is_none());
        assert_eq!(wheel.next_deadline(), Some(deadline));
        assert_eq!(advance(&mut wheel, target), vec![waiter_id(0, 0)]);
        wheel.remove(target);
    }

    #[test]
    fn test_advance_non_expiry_paths() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert_eq!(wheel.next_deadline(), None);

        // Current time rounds down and never moves backward, including while idle.
        for (millis, tick) in [(0, 0), (4, 0), (5, 1), (12, 2), (5, 2)] {
            assert!(
                wheel
                    .advance(wheel.start + Duration::from_millis(millis))
                    .is_none()
            );
            assert_eq!(wheel.current_tick, tick);
        }

        wheel.schedule(waiter_id(0, 0), 5);
        assert!(advance(&mut wheel, 4).is_empty());
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 5)));
        assert_eq!(advance(&mut wheel, 5), vec![waiter_id(0, 0)]);
        wheel.remove(5);
    }

    #[test]
    fn test_schedule_advance_and_deadline_lookup() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(waiter_id(1, 0), 2);
        wheel.schedule(waiter_id(2, 0), 5);
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 2)));

        // New registrations can join a later bucket between service turns.
        assert!(advance(&mut wheel, 1).is_empty());
        wheel.schedule(waiter_id(3, 0), 5);
        assert_eq!(advance(&mut wheel, 2), vec![waiter_id(1, 0)]);
        wheel.remove(2);
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 5)));

        assert_eq!(
            advance(&mut wheel, 5),
            vec![waiter_id(2, 0), waiter_id(3, 0)]
        );

        // Draining returns candidates. Each active registration still needs removal.
        assert_eq!(wheel.active_deadlines, 2);
        wheel.remove(5);
        wheel.remove(5);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_advance_purges_inactive_buckets() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(waiter_id(1, 0), 2);
        wheel.remove(2);
        assert_eq!(wheel.occupied_slots, 1);

        // With no active deadlines, advance clears stale candidates without expiring them.
        assert!(advance(&mut wheel, 10).is_empty());
        assert_eq!(wheel.current_tick, 10);
        assert_eq!(wheel.occupied_slots, 0);
        assert!(wheel.buckets.iter().all(Vec::is_empty));
        assert_eq!(wheel.next_deadline(), None);

        assert!(advance(&mut wheel, 100).is_empty());
        assert_eq!(wheel.current_tick, 100);
        assert_eq!(wheel.occupied_slots, 0);
    }

    #[test]
    fn test_wraparound_range_drain() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert_eq!(wheel.buckets.len(), 32);
        assert!(advance(&mut wheel, 30).is_empty());
        wheel.schedule(waiter_id(3, 0), 33);
        wheel.schedule(waiter_id(1, 0), 31);
        wheel.schedule(waiter_id(2, 0), 33);

        // One advance crosses slot zero and drains both the tail and head ranges.
        assert_eq!(
            advance(&mut wheel, 33),
            vec![waiter_id(1, 0), waiter_id(3, 0), waiter_id(2, 0),]
        );
        wheel.remove(31);
        wheel.remove(33);
        wheel.remove(33);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_multi_word_range_drain() {
        let mut wheel = wheel(Duration::from_millis(500));
        for tick in [63, 64, 65, 100] {
            wheel.schedule(waiter_id(tick as u32, 0), tick);
        }

        // Cross a bitset word boundary, leaving a later bit in that word untouched.
        assert_eq!(
            advance(&mut wheel, 65),
            vec![waiter_id(63, 0), waiter_id(64, 0), waiter_id(65, 0),]
        );
        for tick in [63, 64, 65] {
            wheel.remove(tick);
        }
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 100)));
        assert_eq!(advance(&mut wheel, 100), vec![waiter_id(100, 0)]);
        wheel.remove(100);
    }

    #[test]
    fn test_full_revolution_drain_and_reschedule() {
        for tick in [32, 40, 96] {
            let mut wheel = wheel(Duration::from_millis(100));
            wheel.schedule(waiter_id(1, 0), 20);
            wheel.schedule(waiter_id(2, 0), 5);

            // Advancing by a full revolution or more drains every occupied bucket.
            let mut expired = advance(&mut wheel, tick);
            expired.sort_unstable_by_key(|id| id.0.index);
            assert_eq!(expired, vec![waiter_id(1, 0), waiter_id(2, 0)]);
            wheel.remove(5);
            wheel.remove(20);
            assert_eq!(wheel.occupied_slots, 0);
            assert_eq!(wheel.next_deadline(), None);

            // Reuse the wheel immediately after draining it.
            wheel.schedule(waiter_id(2, 1), tick + 1);
            assert_eq!(advance(&mut wheel, tick + 1), vec![waiter_id(2, 1)]);
            wheel.remove(tick + 1);
        }
    }

    #[test]
    fn test_removal_recomputes_minimum_across_wrap() {
        let mut wheel = wheel(Duration::from_millis(500));
        assert_eq!(wheel.buckets.len(), 128);
        assert!(advance(&mut wheel, 63).is_empty());
        wheel.schedule(waiter_id(0, 0), 64);
        wheel.schedule(waiter_id(1, 0), 64);
        wheel.schedule(waiter_id(2, 0), 100);
        wheel.schedule(waiter_id(3, 0), 129);

        // Neither a later removal nor one of several minimum entries changes the minimum.
        wheel.remove(100);
        wheel.remove(64);
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 64)));

        // Removing the last minimum skips the empty tail word and wraps to slot one.
        wheel.remove(64);
        assert_eq!(wheel.next_deadline(), Some(now_for_tick(&wheel, 129)));
        wheel.remove(129);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_reused_slot_preserves_registration_identity() {
        let mut wheel = wheel(Duration::from_millis(100));
        let old = waiter_id(7, 0);
        let current = waiter_id(7, 1);
        wheel.schedule(old, 5);
        wheel.remove(5);
        wheel.schedule(current, 10);

        // Lazy removal preserves the old identity beside the replacement.
        assert_eq!(advance(&mut wheel, 10), vec![old, current]);

        // The caller rejects the old candidate and removes only the live expiry.
        wheel.remove(10);
        assert_eq!(wheel.active_deadlines, 0);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_completed_deadlines_do_not_accumulate_across_revolutions() {
        let mut wheel = wheel(TICK * 10);
        wheel.schedule(waiter_id(0, 0), 10);

        // Keep one deadline active at every advance, while completing each
        // request before expiry. Neither expiry nor idle cleanup can help.
        for tick in 1..=1024 {
            assert!(advance(&mut wheel, tick).is_empty());
            wheel.schedule(waiter_id(tick as u32, 0), tick + 10);
            wheel.remove(tick + 9);
        }

        assert_eq!(wheel.active_deadlines, 1);
        let retained: usize = wheel.buckets.iter().map(Vec::len).sum();
        assert!(
            retained <= wheel.buckets.len(),
            "retained {retained} records"
        );

        let expired = advance(&mut wheel, 1034);
        assert!(expired.contains(&waiter_id(1024, 0)));
        wheel.remove(1034);
        assert!(advance(&mut wheel, 1035).is_empty());
        assert_eq!(wheel.occupied_slots, 0);
    }

    #[test]
    fn test_inactive_bucket_reuses_storage_without_disturbing_live_deadlines() {
        let mut wheel = wheel(TICK * 10);
        wheel.schedule(waiter_id(0, 0), 10);
        wheel.schedule(waiter_id(1, 0), 10);
        let slot = wheel.slot_index(10);

        // Removal stays lazy. A new deadline beside a live one preserves its candidates.
        wheel.remove(10);
        wheel.schedule(waiter_id(2, 0), 10);
        assert_eq!(wheel.buckets[slot].len(), 3);
        wheel.remove(10);
        wheel.remove(10);
        assert_eq!(wheel.buckets[slot].len(), 3);
        let capacity = wheel.buckets[slot].capacity();

        // Once the bucket is inactive, reuse discards stale records but keeps its storage.
        let current = waiter_id(0, 1);
        wheel.schedule(current, 10);
        assert_eq!(wheel.buckets[slot], vec![current]);
        assert_eq!(wheel.buckets[slot].capacity(), capacity);
        assert_eq!(wheel.occupied_slots, 1);
        assert_eq!(wheel.active_deadlines, 1);

        assert_eq!(advance(&mut wheel, 10), vec![current]);
        wheel.remove(10);
        assert_eq!(wheel.occupied_slots, 0);
        assert_eq!(wheel.active_deadlines, 0);
    }

    #[test]
    fn test_tick_conversion_extremes() {
        assert_eq!(
            TimeoutWheel::duration_to_nanos_saturating(Duration::MAX),
            u64::MAX
        );
        assert_eq!(
            TimeoutWheel::duration_to_nanos_saturating(Duration::new(1, 42)),
            1_000_000_042
        );

        // Absolute offsets may exceed u64 nanoseconds even when each tick fits.
        let start = Instant::now();
        let tick = Duration::from_nanos(u64::MAX);
        let wheel = TimeoutWheel::new(TICK, tick, start);
        assert_eq!(wheel.instant_at_tick(2), start + tick * 2);
    }

    #[test]
    fn test_schedule_rejects_out_of_span_ticks() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 10).is_empty());

        // Past, current, and full-revolution targets cannot share the live wheel span.
        for tick in [9, 10, 10 + wheel.buckets.len() as Tick] {
            assert!(
                catch_unwind(AssertUnwindSafe(|| wheel.schedule(waiter_id(0, 0), tick))).is_err()
            );
        }
    }

    #[test]
    fn test_remove_rejects_untracked_deadlines() {
        for tracked in [false, true] {
            let mut wheel = wheel(Duration::from_millis(100));
            if tracked {
                wheel.schedule(waiter_id(0, 0), 1);
            }

            // Reject an untracked tick both on an empty wheel and beside a live deadline.
            assert!(catch_unwind(AssertUnwindSafe(|| wheel.remove(2))).is_err());
        }
    }
}
