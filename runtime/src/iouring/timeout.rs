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
//! - Expiry entries carry waiter slot plus scheduled tick identity so callers can safely
//!   ignore stale entries after slot reuse.
//! - Buckets are drained in place, so inner `Vec` capacity is retained and reused across
//!   cycles to reduce allocations.
//! - When no active deadlines remain, stale bucket entries are purged in bulk so
//!   occupancy metadata does not drift and cause spurious wakeups.
//!
//! Reference: <https://www.cs.columbia.edu/~nahum/w6998/papers/sosp87-timing-wheels.pdf>

use super::WaiterId;
use std::time::{Duration, Instant};

/// Monotonic timeout-wheel tick in the wheel's local time domain.
///
/// This is derived from `start` and `tick_nanos` inside [`TimeoutWheel::advance`]
/// and [`TimeoutWheel::target_tick`]. It is not wall-clock time and should be
/// treated as an opaque counter.
pub type Tick = u64;

/// Entry yielded when a wheel bucket expires.
///
/// Includes waiter identity and target tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutEntry {
    /// Stable waiter identity to inspect.
    pub waiter_id: WaiterId,
    /// Tick the waiter was originally scheduled for.
    pub target_tick: Tick,
}

impl TimeoutEntry {
    const fn new(waiter_id: WaiterId, target_tick: Tick) -> Self {
        Self {
            waiter_id,
            target_tick,
        }
    }
}

/// Single-level (non-hierarchical) hashed timing wheel used for deadline tracking.
pub struct TimeoutWheel {
    /// Bitmask used to map ticks to slot indices.
    slot_mask: usize,
    /// Fixed ring of wheel slots, each slot stores a bucket of timeout entries.
    ///
    /// A slot is chosen by `tick & slot_mask`. Multiple target ticks can map to
    /// the same slot over time, and each slot bucket may contain multiple entries.
    buckets: Vec<Vec<TimeoutEntry>>,
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
    /// Maximum timeout horizon used for deadline clamping.
    max_timeout_nanos: u64,
    /// Tick size in nanoseconds.
    tick_nanos: u64,
    /// Tick epoch used by `tick_at`.
    start: Instant,
}

impl TimeoutWheel {
    /// Largest supported operation timeout, using 365 days per year.
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);

    /// Maximum allocation for the single-level wheel.
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
    /// the timeout cannot exceed 30 years, and the layout cannot exceed
    /// 1,048,576 slots. Duration conversion and size rounding are checked before
    /// any memory is allocated.
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

    /// Return the validated slot count for an already converted tick duration.
    fn slots_for(max_timeout: Duration, tick_nanos: u64) -> usize {
        Self::validate_layout(max_timeout, Duration::from_nanos(tick_nanos))
            .expect("invalid timeout wheel layout")
    }

    /// Create a timeout wheel.
    ///
    /// - `tick` defines the wheel granularity.
    /// - `max_timeout` defines the scheduling horizon (deadlines are clamped to
    ///   at most this distance).
    /// - `start` is the epoch used to convert `Instant` values into wheel ticks.
    ///
    /// The slot count is rounded up to a power of two for fast masking.
    ///
    /// Panics if [`Self::validate_layout`] rejects the configuration.
    pub fn new(max_timeout: Duration, tick: Duration, start: Instant) -> Self {
        let tick_nanos = u64::try_from(tick.as_nanos()).expect("timeout wheel tick overflow");
        let slots = Self::slots_for(max_timeout, tick_nanos);
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

    /// Compute a target timeout tick for `deadline`.
    ///
    /// Returns:
    /// - `None` if `deadline` is already expired in the current wheel tick domain.
    /// - `Some(tick)` for schedulable deadlines, clamped to at most
    ///   `current_tick + max_timeout_ticks`.
    ///
    /// This does not read wall-clock time, callers are expected to keep
    /// `current_tick` fresh by calling [`Self::advance`] each loop iteration.
    pub fn target_tick(&self, deadline: Instant) -> Option<Tick> {
        let now = self.instant_at_tick(self.current_tick);
        let limit = now
            .checked_add(Duration::from_nanos(self.max_timeout_nanos))
            .expect("timeout wheel horizon overflow");
        self.checked_target_tick(deadline.min(limit), now)
            .expect("clamped timeout wheel deadline must fit")
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
    /// Callers should call [`Self::advance`] before scheduling in each loop
    /// iteration so `current_tick` reflects recent wall-clock progress. Scheduling
    /// against a stale `current_tick` can extend effective timeout latency.
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

        // Append timeout candidate, stale entries are filtered by caller on drain.
        self.buckets[slot].push(TimeoutEntry::new(id, target_tick));
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
        // Decrement global count of active deadlines.
        self.active_deadlines -= 1;

        // Decrement active deadline count for this slot.
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
    /// at cancellation time.
    ///
    /// When no active deadlines exist, this still advances `current_tick` and may
    /// purge stale occupied buckets.
    pub fn advance(&mut self, now: Instant) -> Option<Vec<TimeoutEntry>> {
        let elapsed = now.saturating_duration_since(self.start);
        let now_tick = Self::duration_to_nanos_saturating(elapsed) / self.tick_nanos;

        if now_tick <= self.current_tick {
            // Time did not advance in wheel domain.
            return None;
        }

        // Update current tick
        let previous_tick = std::mem::replace(&mut self.current_tick, now_tick);

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

    /// Return timeout duration until the next active deadline tick.
    ///
    /// The returned duration is relative to `current_tick` (the last tick passed to
    /// `advance`), not relative to wall-clock `Instant::now()`.
    ///
    /// For precise results, callers should consume entries returned by `advance` and
    /// call `remove` for each active expiry before querying this method.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.next_deadline_at().map(|deadline| {
            deadline.saturating_duration_since(self.instant_at_tick(self.current_tick))
        })
    }

    /// Return the absolute instant of the next active deadline tick.
    ///
    /// Deriving this from the wheel epoch avoids extending the wait when user
    /// callbacks run between deadline service and parking. As with
    /// [`Self::next_deadline`], remove active expiries before querying it.
    pub fn next_deadline_at(&self) -> Option<Instant> {
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
    fn drain_occupied_buckets(&mut self, mut drain: impl FnMut(&mut Vec<TimeoutEntry>)) {
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
    fn drain_occupied_range(&mut self, start: usize, end: usize, expired: &mut Vec<TimeoutEntry>) {
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
    use std::panic::{AssertUnwindSafe, catch_unwind};

    const TICK: Duration = Duration::from_millis(5);

    fn wheel(max_timeout: Duration) -> TimeoutWheel {
        TimeoutWheel::new(max_timeout, TICK, Instant::now())
    }

    fn now_for_tick(wheel: &TimeoutWheel, tick: Tick) -> Instant {
        wheel.start + Duration::from_nanos(tick.saturating_mul(wheel.tick_nanos))
    }

    fn advance(wheel: &mut TimeoutWheel, now_tick: Tick) -> Vec<TimeoutEntry> {
        wheel
            .advance(now_for_tick(wheel, now_tick))
            .unwrap_or_default()
    }

    #[test]
    fn test_tick_math_and_target_tick_cases() {
        let tick_nanos = TimeoutWheel::duration_to_nanos_saturating(TICK);
        // 60s / 5ms = 12_000 ticks, plus 2 guard ticks => 12_002, next pow2 => 16_384.
        assert_eq!(
            TimeoutWheel::slots_for(Duration::from_secs(60), tick_nanos),
            16_384
        );
        assert_eq!(
            TimeoutWheel::slots_for(Duration::from_nanos(1), tick_nanos),
            4
        );

        let start = Instant::now();
        let mut wheel = TimeoutWheel::new(Duration::from_millis(100), TICK, start);
        for (at, expected) in [(0u64, 0u64), (4, 0), (5, 1), (12, 2)] {
            let elapsed = (start + Duration::from_millis(at)).saturating_duration_since(start);
            let tick = TimeoutWheel::duration_to_nanos_saturating(elapsed) / tick_nanos;
            assert_eq!(tick, expected);
        }

        // Past deadline(s) are already expired.
        let past_deadline = start.checked_sub(Duration::from_millis(1)).unwrap_or(start);
        assert_eq!(wheel.target_tick(past_deadline), None);
        assert_eq!(wheel.target_tick(start), None);

        // Very far deadline clamps to max_timeout (100ms => 20 ticks at 5ms).
        let far_deadline = start + Duration::from_secs(10);
        assert_eq!(wheel.target_tick(far_deadline), Some(20));

        // Target tick should be computed relative to current_tick after advances.
        assert!(advance(&mut wheel, 7).is_empty());
        let now = start + Duration::from_millis(35);
        let deadline = now + Duration::from_millis(12); // ceil(12/5)=3 ticks.
        assert_eq!(wheel.target_tick(deadline), Some(10));
    }

    #[test]
    fn test_checked_layout_limits() {
        assert!(TimeoutWheel::validate_layout(Duration::ZERO, TICK).is_err());
        assert!(TimeoutWheel::validate_layout(TICK, Duration::ZERO).is_err());
        assert!(TimeoutWheel::validate_layout(TICK, Duration::MAX).is_err());
        assert!(TimeoutWheel::validate_layout(Duration::MAX, TICK).is_err());
        assert!(
            TimeoutWheel::validate_layout(
                TimeoutWheel::MAX_TIMEOUT + Duration::from_nanos(1),
                Duration::from_secs(3600)
            )
            .is_err()
        );
        assert!(
            TimeoutWheel::validate_layout(TimeoutWheel::MAX_TIMEOUT, Duration::from_secs(3600))
                .is_ok()
        );
        let limit = TimeoutWheel::MAX_SLOTS as u64;
        assert_eq!(
            TimeoutWheel::validate_layout(Duration::from_nanos(limit - 2), Duration::from_nanos(1)),
            Ok(TimeoutWheel::MAX_SLOTS)
        );
        assert!(
            TimeoutWheel::validate_layout(Duration::from_nanos(limit - 1), Duration::from_nanos(1))
                .is_err()
        );
    }

    #[test]
    fn test_checked_deadline_horizon_and_alignment() {
        let start = Instant::now();
        let horizon = Duration::from_millis(15);
        let mut wheel = TimeoutWheel::new(horizon, TICK, start);
        // At this alignment a full-horizon deadline needs four future ticks.
        // Four slots would alias the current tick, so the layout needs eight.
        assert_eq!(wheel.buckets.len(), 8);
        let now = start + Duration::from_millis(1);
        wheel.advance(now);
        assert_eq!(wheel.checked_target_tick(now, now), Ok(None));
        assert_eq!(wheel.checked_target_tick(now + horizon, now), Ok(Some(4)));
        assert!(
            wheel
                .checked_target_tick(now + horizon + Duration::from_nanos(1), now)
                .is_err()
        );
        wheel.schedule(WaiterId::new(0, 0), 4);
        assert_eq!(
            wheel.next_deadline_at(),
            Some(start + Duration::from_millis(20))
        );
        wheel.remove(4);
        assert_eq!(wheel.next_deadline_at(), None);

        // Long idle time and long user polls must be reflected before accepting
        // a newly created deadline. The valid deadline must never be clamped.
        let now = start + Duration::from_secs(60) + Duration::from_millis(1);
        assert!(wheel.checked_target_tick(now + horizon, now).is_err());
        wheel.advance(now);
        assert_eq!(
            wheel.checked_target_tick(now + horizon, now),
            Ok(Some(12_004))
        );
        wheel.schedule(WaiterId::new(0, 1), 12_004);
        let absolute = start + Duration::from_millis(60_020);
        assert_eq!(wheel.next_deadline_at(), Some(absolute));
        wheel.advance(now + Duration::from_millis(6));
        assert_eq!(wheel.next_deadline_at(), Some(absolute));
    }

    #[test]
    fn test_advance_non_expiry_paths() {
        // Empty wheel: advancing only updates current tick.
        let mut empty = wheel(Duration::from_millis(100));
        assert!(advance(&mut empty, 10).is_empty());
        assert_eq!(empty.current_tick, 10);
        assert_eq!(empty.next_deadline(), None);

        // No-op path: now tick does not move forward.
        let mut no_op = wheel(Duration::from_millis(100));
        no_op.schedule(WaiterId::new(1, 0), 2);
        assert!(advance(&mut no_op, 0).is_empty());
        assert_eq!(no_op.current_tick, 0);

        // Active deadline exists, but it is still in the future.
        let mut future = wheel(Duration::from_millis(100));
        future.schedule(WaiterId::new(7, 0), 10);
        assert!(future.advance(now_for_tick(&future, 5)).is_none());

        // Earliest active deadline has not arrived yet.
        let mut none_due = wheel(Duration::from_millis(100));
        none_due.schedule(WaiterId::new(7, 0), 2);
        assert!(none_due.advance(now_for_tick(&none_due, 1)).is_none());
    }

    #[test]
    fn test_schedule_after_advance_via_public_api() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 10).is_empty());

        let now = wheel.start + Duration::from_millis(50); // tick 10
        let deadline = now + Duration::from_millis(10); // +2 ticks => tick 12
        let target_tick = wheel
            .target_tick(deadline)
            .expect("deadline should be schedulable");
        assert_eq!(target_tick, 12);
        wheel.schedule(WaiterId::new(1, 0), target_tick);
        assert!(advance(&mut wheel, 11).is_empty());
        assert_eq!(
            advance(&mut wheel, 12),
            vec![TimeoutEntry::new(WaiterId::new(1, 0), 12)]
        );
    }

    #[test]
    fn test_schedule_advance_and_timeout_lookup() {
        let mut wheel = wheel(Duration::from_millis(100));

        wheel.schedule(WaiterId::new(1, 0), 2);
        wheel.schedule(WaiterId::new(2, 0), 5);

        // Earliest target tick is 2 => 2 * 5ms from current tick 0.
        assert_eq!(wheel.next_deadline(), Some(Duration::from_millis(10)));

        assert!(advance(&mut wheel, 1).is_empty());
        assert_eq!(
            advance(&mut wheel, 2),
            vec![TimeoutEntry::new(WaiterId::new(1, 0), 2)]
        );
        wheel.remove(2);
        assert_eq!(wheel.next_deadline(), Some(Duration::from_millis(15)));
        assert_eq!(
            advance(&mut wheel, 5),
            vec![TimeoutEntry::new(WaiterId::new(2, 0), 5)]
        );
        wheel.remove(5);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_interleaved_schedule_advance_cycles() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);

        assert!(advance(&mut wheel, 1).is_empty());
        wheel.schedule(WaiterId::new(2, 0), 4);

        assert_eq!(
            advance(&mut wheel, 2),
            vec![TimeoutEntry::new(WaiterId::new(1, 0), 2)]
        );
        wheel.remove(2);

        assert!(advance(&mut wheel, 3).is_empty());
        assert_eq!(
            advance(&mut wheel, 4),
            vec![TimeoutEntry::new(WaiterId::new(2, 0), 4)]
        );
        wheel.remove(4);
        assert_eq!(wheel.next_deadline(), None);
    }

    #[test]
    fn test_advance_no_active_fast_path_and_stale_purge() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);
        wheel.remove(2);

        // With no active deadlines, the first advance purges stale occupancy and
        // still moves the wheel clock forward.
        let expired = advance(&mut wheel, 10);
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick, 10);
        assert_eq!(wheel.occupied_slots, 0);
        assert_eq!(wheel.next_deadline(), None);

        // Subsequent idle advances are no-ops for occupancy metadata.
        let expired = advance(&mut wheel, 100);
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick, 100);
        assert_eq!(wheel.occupied_slots, 0);
    }

    #[test]
    fn test_advance_returns_all_waiters_from_same_bucket() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);
        wheel.schedule(WaiterId::new(2, 0), 2);

        assert_eq!(
            advance(&mut wheel, 2),
            vec![
                TimeoutEntry::new(WaiterId::new(1, 0), 2),
                TimeoutEntry::new(WaiterId::new(2, 0), 2)
            ]
        );
    }

    #[test]
    fn test_wraparound_deadline_and_range_drain() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 30).is_empty());
        wheel.schedule(WaiterId::new(3, 0), 33);

        // current=30, target=33 => 3 ticks of 5ms.
        assert_eq!(wheel.next_deadline(), Some(Duration::from_millis(15)));

        // Add an earlier wrapped slot so one advance drains tail and head ranges.
        wheel.schedule(WaiterId::new(1, 0), 31);
        wheel.schedule(WaiterId::new(2, 0), 33);

        assert_eq!(
            advance(&mut wheel, 33),
            vec![
                TimeoutEntry::new(WaiterId::new(1, 0), 31),
                TimeoutEntry::new(WaiterId::new(3, 0), 33),
                TimeoutEntry::new(WaiterId::new(2, 0), 33)
            ]
        );
    }

    #[test]
    fn test_multi_word_bitset_end_to_end_advance() {
        let mut wheel = wheel(Duration::from_millis(500));
        wheel.schedule(WaiterId::new(1, 0), 63);
        wheel.schedule(WaiterId::new(2, 0), 64);
        wheel.schedule(WaiterId::new(3, 0), 65);

        assert_eq!(
            advance(&mut wheel, 65),
            vec![
                TimeoutEntry::new(WaiterId::new(1, 0), 63),
                TimeoutEntry::new(WaiterId::new(2, 0), 64),
                TimeoutEntry::new(WaiterId::new(3, 0), 65)
            ]
        );
    }

    #[test]
    fn test_full_revolution_drain_and_reschedule() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 20);
        wheel.schedule(WaiterId::new(2, 0), 5);

        // slots=32 for max_timeout=100ms. Jumping by >=32 ticks expires all buckets.
        let mut expired = wheel.advance(now_for_tick(&wheel, 40)).unwrap_or_default();
        expired.sort_unstable_by_key(|entry| entry.waiter_id.index());
        assert_eq!(
            expired,
            vec![
                TimeoutEntry::new(WaiterId::new(1, 0), 20),
                TimeoutEntry::new(WaiterId::new(2, 0), 5)
            ]
        );
        wheel.remove(20);
        wheel.remove(5);
        assert_eq!(wheel.next_deadline(), None);

        // Wheel remains usable after a full-revolution drain.
        wheel.schedule(WaiterId::new(2, 0), 41);
        assert_eq!(
            advance(&mut wheel, 41),
            vec![TimeoutEntry::new(WaiterId::new(2, 0), 41)]
        );
    }

    #[test]
    fn test_advance_returns_none_when_due_scan_finds_no_occupied_slots() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 5);

        // Corrupt only bucket-occupancy metadata so active state says "due",
        // but the scan sees no occupied buckets and returns None.
        wheel.occupied.fill(0);
        wheel.occupied_slots = 0;
        assert!(wheel.advance(now_for_tick(&wheel, 5)).is_none());
    }

    #[test]
    fn test_min_scheduled_tick_update_paths() {
        // Case 1: early advance before minimum tick should not lose the entry.
        let mut wheel_future = wheel(Duration::from_millis(500));
        wheel_future.schedule(WaiterId::new(9, 0), 100);

        // now_tick is before earliest scheduled tick, so advance should fast-skip.
        assert!(advance(&mut wheel_future, 50).is_empty());
        assert_eq!(wheel_future.current_tick, 50);
        assert_eq!(wheel_future.min_scheduled_tick, 100);

        // Once we reach the target tick, the entry should still expire.
        assert_eq!(
            advance(&mut wheel_future, 100),
            vec![TimeoutEntry::new(WaiterId::new(9, 0), 100)]
        );
        wheel_future.remove(100);

        // Case 2: removing the minimum should recompute to the next active tick.
        let mut wheel_recompute = wheel(Duration::from_millis(100));
        wheel_recompute.schedule(WaiterId::new(1, 0), 5);
        wheel_recompute.schedule(WaiterId::new(2, 0), 10);
        assert_eq!(
            advance(&mut wheel_recompute, 5),
            vec![TimeoutEntry::new(WaiterId::new(1, 0), 5)]
        );
        wheel_recompute.remove(5);
        assert_eq!(wheel_recompute.min_scheduled_tick, 10);
        assert_eq!(
            wheel_recompute.next_deadline(),
            Some(Duration::from_millis(25))
        );

        // Case 3: removing a non-minimum tick should keep the minimum unchanged.
        let mut wheel_non_min = wheel(Duration::from_millis(100));
        wheel_non_min.schedule(WaiterId::new(1, 0), 5);
        wheel_non_min.schedule(WaiterId::new(2, 0), 10);
        wheel_non_min.remove(10);
        assert_eq!(wheel_non_min.min_scheduled_tick, 5);
        assert_eq!(
            wheel_non_min.next_deadline(),
            Some(Duration::from_millis(25))
        );
    }

    #[test]
    fn test_reused_slot_stale_entry_preserves_tick_identity() {
        let mut wheel = wheel(Duration::from_millis(100));

        wheel.schedule(WaiterId::new(7, 0), 5);
        wheel.remove(5); // completed early; stale entry stays in bucket until drain
        wheel.schedule(WaiterId::new(7, 0), 10); // slot reused for new waiter

        // When the later deadline is reached, both stale and live entries can be
        // returned. Tick identity disambiguates them.
        assert_eq!(
            advance(&mut wheel, 10),
            vec![
                TimeoutEntry::new(WaiterId::new(7, 0), 5),
                TimeoutEntry::new(WaiterId::new(7, 0), 10)
            ]
        );
    }

    #[test]
    fn test_duration_to_nanos_saturating_extremes() {
        assert_eq!(
            TimeoutWheel::duration_to_nanos_saturating(Duration::MAX),
            u64::MAX
        );
        assert_eq!(
            TimeoutWheel::duration_to_nanos_saturating(Duration::new(1, 42)),
            1_000_000_042
        );
    }

    #[test]
    fn test_construction_panics_for_invalid_inputs() {
        let tick_nanos = TimeoutWheel::duration_to_nanos_saturating(TICK);

        // Zero max timeout is rejected when deriving slot count.
        let zero_timeout = catch_unwind(AssertUnwindSafe(|| {
            let _ = TimeoutWheel::slots_for(Duration::ZERO, tick_nanos);
        }));
        assert!(zero_timeout.is_err());

        // Zero tick nanoseconds are rejected by slot derivation.
        let zero_tick_nanos = catch_unwind(AssertUnwindSafe(|| {
            let _ = TimeoutWheel::slots_for(Duration::from_millis(1), 0);
        }));
        assert!(zero_tick_nanos.is_err());

        // Public constructor rejects zero tick duration.
        let zero_tick = catch_unwind(AssertUnwindSafe(|| {
            let _ = TimeoutWheel::new(Duration::from_millis(100), Duration::ZERO, Instant::now());
        }));
        assert!(zero_tick.is_err());
    }

    #[test]
    fn test_compute_min_scheduled_tick_cases() {
        let empty_wheel = wheel(Duration::from_millis(100));
        assert_eq!(empty_wheel.compute_min_scheduled_tick(), Tick::MAX);

        let mut wrapped_wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wrapped_wheel, 30).is_empty());
        wrapped_wheel.schedule(WaiterId::new(1, 0), 33);
        assert_eq!(wrapped_wheel.compute_min_scheduled_tick(), 33);

        // Multi-word wrap case: with 128 slots and current tick at 63,
        // scan starts at slot 64 and wraps to slot 1.
        let mut multi_word = wheel(Duration::from_millis(500));
        assert!(advance(&mut multi_word, 63).is_empty());
        multi_word.active_occupied[0] |= 1u64 << 1;
        assert_eq!(multi_word.compute_min_scheduled_tick(), 129);
    }

    #[test]
    fn test_compute_min_scheduled_tick_empty_wrapped_tail() {
        let mut wheel = wheel(Duration::from_millis(100));
        let last_slot_tick = wheel.buckets.len() as Tick - 1;
        assert!(advance(&mut wheel, last_slot_tick).is_empty());

        // No active bits: first scan over [start, end) is empty; wrapped scan is
        // [0, 0) and should also return None.
        wheel.active_occupied.fill(0);
        assert_eq!(wheel.compute_min_scheduled_tick(), Tick::MAX);
    }

    #[test]
    fn test_drain_occupied_range_empty_interval_noop() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);

        let mut expired = Vec::new();
        wheel.drain_occupied_range(7, 7, &mut expired);
        assert!(expired.is_empty());
        assert_eq!(wheel.occupied_slots, 1);
    }

    #[test]
    fn test_invariant_assertion_paths() {
        {
            let mut wheel = wheel(Duration::from_millis(100));
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.schedule(WaiterId::new(1, 0), 0);
            }));
            assert!(
                err.is_err(),
                "schedule should reject non-future target_tick"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            let too_far = wheel.buckets.len() as Tick;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.schedule(WaiterId::new(1, 0), too_far);
            }));
            assert!(err.is_err(), "schedule should reject horizon overflow");
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.remove(1);
            }));
            assert!(
                err.is_err(),
                "remove should reject active_deadlines underflow"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            wheel.active_deadlines = 1;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.remove(1);
            }));
            assert!(
                err.is_err(),
                "remove should reject missing active slot count"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            let slot = 1usize;
            wheel.occupied[slot / TimeoutWheel::WORD_BITS] |=
                1u64 << (slot % TimeoutWheel::WORD_BITS);
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.schedule(WaiterId::new(1, 0), 1);
            }));
            assert!(
                err.is_err(),
                "schedule should reject duplicate occupied bit"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            wheel.occupied[0] |= 1;
            wheel.occupied_slots = 1;
            let mut expired = Vec::new();
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.drain_occupied_range(0, 1, &mut expired);
            }));
            assert!(
                err.is_err(),
                "drain_occupied_range_into should reject empty occupied bucket"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            let invalid_slot = wheel.buckets.len();
            wheel.occupied[invalid_slot / TimeoutWheel::WORD_BITS] |=
                1u64 << (invalid_slot % TimeoutWheel::WORD_BITS);
            wheel.occupied_slots = 1;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.drain_occupied_buckets(|_| {});
            }));
            assert!(
                err.is_err(),
                "drain_occupied_buckets should reject out-of-range occupied bit"
            );
        }
    }
}
