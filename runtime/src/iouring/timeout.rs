//! Timeout wheel for io_uring user space waiter deadlines.
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
//! - Full-revolution advances bulk-clear active tracking metadata because all active
//!   deadlines are known to have expired, `advance` reports this so callers can skip
//!   per-entry `remove_active_deadline` calls.
//!
//! Reference: <https://www.cs.columbia.edu/~nahum/w6998/papers/sosp87-timing-wheels.pdf>

use super::WaiterId;
use std::time::{Duration, Instant};

/// Monotonic timeout-wheel tick in the wheel's local time domain.
///
/// This is derived from `start` and `tick_nanos` (see [`TimeoutWheel::tick_at`]).
/// It is not wall-clock time and should be treated as an opaque counter.
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
    /// Buckets of waiter slot indices keyed by target tick.
    buckets: Vec<Vec<TimeoutEntry>>,
    /// Occupancy bitset for buckets that contain any entries (active or stale).
    occupied: Vec<u64>,
    /// Number of occupied bucket slots currently represented in `occupied`.
    occupied_slots: usize,
    /// Count of active deadlines by slot index.
    active_counts: Vec<u32>,
    /// Occupancy bitset for slots with at least one active deadline.
    active_occupied: Vec<u64>,
    /// Monotonic tick processed by the wheel.
    current_tick: Tick,
    /// Earliest active deadline tick (`Tick::MAX` when empty).
    min_scheduled_tick: Tick,
    /// Count of currently active deadline-tracked waiters.
    active_deadlines: usize,
    /// Maximum timeout horizon in nanoseconds.
    max_timeout_nanos: u64,
    /// Tick duration in nanoseconds.
    tick_nanos: u64,
    /// Wheel epoch.
    start: Instant,
}

impl TimeoutWheel {
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

    /// Return the number of slots required to cover `max_timeout`.
    ///
    /// The result is rounded up to a power of two for fast modulo-by-mask
    /// indexing.
    fn slots_for(max_timeout: Duration, tick_nanos: u64) -> usize {
        assert!(
            !max_timeout.is_zero(),
            "max_timeout must be non-zero for timeout wheel"
        );
        assert!(tick_nanos > 0, "timeout wheel tick must be non-zero");
        let max_timeout_nanos = Self::duration_to_nanos_saturating(max_timeout);
        let required_ticks = max_timeout_nanos.div_ceil(tick_nanos) + 1;
        usize::try_from(required_ticks)
            .expect("timeout wheel size overflow")
            .checked_next_power_of_two()
            .expect("timeout wheel size overflow")
    }

    /// Create a wheel with horizon >= `max_timeout` and tick size `tick`.
    pub fn new(max_timeout: Duration, tick: Duration, start: Instant) -> Self {
        let tick_nanos = Self::duration_to_nanos_saturating(tick);
        assert!(tick_nanos > 0, "timeout wheel tick must be non-zero");
        let max_timeout = max_timeout.max(tick);
        let slots = Self::slots_for(max_timeout, tick_nanos);

        let mut buckets = Vec::with_capacity(slots);
        buckets.resize_with(slots, Vec::new);

        Self {
            slot_mask: slots - 1,
            buckets,
            occupied: vec![0; slots.div_ceil(64)],
            occupied_slots: 0,
            active_counts: vec![0; slots],
            active_occupied: vec![0; slots.div_ceil(64)],
            current_tick: 0,
            min_scheduled_tick: Tick::MAX,
            active_deadlines: 0,
            max_timeout_nanos: Self::duration_to_nanos_saturating(max_timeout),
            tick_nanos,
            start,
        }
    }

    /// Convert wall-clock `now` into the wheel's monotonic tick domain.
    pub fn tick_at(&self, now: Instant) -> Tick {
        let elapsed = now.saturating_duration_since(self.start);
        Self::duration_to_nanos_saturating(elapsed) / self.tick_nanos
    }

    /// Compute a target timeout tick for `deadline`.
    ///
    /// Deadlines are clamped into `[tick, max_timeout]`.
    pub fn target_tick_for_deadline(&self, deadline: Instant, now: Instant) -> Tick {
        let delay_nanos =
            Self::duration_to_nanos_saturating(deadline.saturating_duration_since(now))
                .clamp(self.tick_nanos, self.max_timeout_nanos);
        let ticks = delay_nanos.div_ceil(self.tick_nanos);
        self.current_tick.saturating_add(ticks)
    }

    /// Schedule `waiter_id` for timeout at `target_tick`.
    ///
    /// Invariants:
    /// - `target_tick` must be in the future relative to `current_tick`.
    /// - `target_tick` must be within wheel horizon (`target_tick - current_tick < slots`).
    /// - Callers must eventually pair this with exactly one `remove_active_deadline`.
    pub fn schedule(&mut self, waiter_id: WaiterId, target_tick: Tick) {
        let delta = target_tick.wrapping_sub(self.current_tick);
        assert!(delta > 0, "target_tick must be in the future");
        assert!(
            delta < self.buckets.len() as Tick,
            "target_tick exceeds timeout wheel horizon"
        );

        let slot = self.slot_index(target_tick);
        let bucket_was_empty = self.buckets[slot].is_empty();
        self.buckets[slot].push(TimeoutEntry::new(waiter_id, target_tick));
        self.active_deadlines += 1;

        let count = &mut self.active_counts[slot];
        *count = count
            .checked_add(1)
            .expect("active deadline count overflow");
        if *count == 1 {
            self.set_active_occupied(slot);
        }

        self.min_scheduled_tick = self.min_scheduled_tick.min(target_tick);
        if bucket_was_empty {
            self.set_occupied(slot);
        }
    }

    /// Mark one waiter as leaving active deadline tracking at `target_tick`.
    pub fn remove_active_deadline(&mut self, target_tick: Tick) {
        assert!(
            self.active_deadlines > 0,
            "active_deadlines underflow in remove_active_deadline"
        );
        self.active_deadlines -= 1;

        let slot = self.slot_index(target_tick);
        let count = &mut self.active_counts[slot];
        assert!(
            *count > 0,
            "active deadline count missing in remove_active_deadline"
        );
        *count -= 1;
        if *count == 0 {
            self.clear_active_occupied(slot);
        }

        if self.active_deadlines == 0 {
            self.min_scheduled_tick = Tick::MAX;
            return;
        }
        if target_tick != self.min_scheduled_tick {
            return;
        }
        // The wheel horizon guarantees `target_tick - current_tick < slots`, so two
        // distinct active ticks cannot alias to the same slot at once. If this slot
        // still has active entries, they must be for the same `target_tick`, and the
        // minimum tick is unchanged.
        if self.active_counts[slot] != 0 {
            return;
        }
        self.min_scheduled_tick = self.compute_min_active_tick();
    }

    /// Return whether any active deadline-tracked waiters exist.
    pub const fn has_active_deadlines(&self) -> bool {
        self.active_deadlines != 0
    }

    /// Purge stale occupied buckets when no active deadlines remain.
    pub fn maybe_purge_idle_stale(&mut self) {
        if self.active_deadlines == 0 && self.occupied_slots != 0 {
            self.clear_all_occupied();
        }
    }

    /// Align `current_tick` to `now` when the wheel is idle.
    ///
    /// This should be called before scheduling new deadlines after idle periods
    /// where `advance` may have been skipped.
    pub fn align_idle_to_now(&mut self, now: Instant) {
        if self.active_deadlines != 0 {
            return;
        }
        let now_tick = self.tick_at(now);
        if now_tick > self.current_tick {
            self.current_tick = now_tick;
        }
        self.maybe_purge_idle_stale();
    }

    /// Advance the wheel to `now_tick`, appending expired entries to `expired`.
    ///
    /// This form allows callers to reuse a scratch buffer across calls.
    ///
    /// Returns `true` when this call bulk-cleared all active tracking metadata
    /// due to a full-revolution drain.
    ///
    /// Contract:
    /// - This method clears `expired` only when it actually performs a drain.
    /// - If this method returns `false`, callers should process every returned
    ///   active timeout entry and call `remove_active_deadline` before relying
    ///   on `timeout_until_next_deadline`.
    pub fn advance(&mut self, now_tick: Tick, expired: &mut Vec<TimeoutEntry>) -> bool {
        if now_tick <= self.current_tick {
            return false;
        }
        if self.active_deadlines == 0 {
            self.current_tick = now_tick;
            if self.occupied_slots != 0 {
                self.clear_all_occupied();
            }
            return false;
        }
        if now_tick < self.min_scheduled_tick {
            self.current_tick = now_tick;
            return false;
        }

        expired.clear();

        let elapsed = now_tick - self.current_tick;
        if elapsed >= self.buckets.len() as Tick {
            // At most `slots - 1` ticks can remain in-horizon for active entries.
            // If we advanced by at least one full revolution, every active
            // deadline must have expired.
            self.current_tick = now_tick;
            self.drain_all_occupied_into(expired);
            self.clear_all_active();
            return true;
        }

        let start_slot = self.slot_index(self.current_tick + 1);
        let end_slot = self.slot_index(now_tick);
        self.current_tick = now_tick;

        if start_slot <= end_slot {
            self.drain_occupied_range_into(start_slot, end_slot + 1, expired);
        } else {
            self.drain_occupied_range_into(start_slot, self.buckets.len(), expired);
            self.drain_occupied_range_into(0, end_slot + 1, expired);
        }
        false
    }

    /// Return timeout duration until the next active deadline tick.
    ///
    /// The returned duration is relative to `current_tick` (the last tick passed
    /// to `advance`), not relative to wall-clock `Instant::now()`.
    ///
    /// For precise results, callers should consume entries returned by
    /// `advance` and call `remove_active_deadline` for each active expiry
    /// before querying this method.
    pub const fn timeout_until_next_deadline(&self) -> Option<Duration> {
        if self.min_scheduled_tick == Tick::MAX {
            return None;
        }
        let ticks = self.min_scheduled_tick.saturating_sub(self.current_tick);
        let nanos = self.tick_nanos.saturating_mul(ticks);
        Some(Duration::from_nanos(nanos))
    }

    /// Visit each occupied bucket and clear its occupancy bit.
    fn drain_occupied_buckets(&mut self, mut f: impl FnMut(&mut Vec<TimeoutEntry>)) {
        for word_index in 0..self.occupied.len() {
            let mut word = self.occupied[word_index];
            if word == 0 {
                continue;
            }
            self.occupied[word_index] = 0;
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let slot = word_index * 64 + bit;
                assert!(
                    slot < self.buckets.len(),
                    "occupied bitset contains out-of-range slot index"
                );
                f(&mut self.buckets[slot]);
                word &= word - 1;
            }
        }
        self.occupied_slots = 0;
    }

    fn clear_all_occupied(&mut self) {
        self.drain_occupied_buckets(Vec::clear);
    }

    fn clear_all_active(&mut self) {
        for word_index in 0..self.active_occupied.len() {
            let mut word = self.active_occupied[word_index];
            if word == 0 {
                continue;
            }
            self.active_occupied[word_index] = 0;
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let slot = word_index * 64 + bit;
                assert!(
                    slot < self.active_counts.len(),
                    "active bitset contains out-of-range slot index"
                );
                self.active_counts[slot] = 0;
                word &= word - 1;
            }
        }
        self.active_deadlines = 0;
        self.min_scheduled_tick = Tick::MAX;
    }

    #[inline]
    const fn slot_index(&self, tick: Tick) -> usize {
        (tick as usize) & self.slot_mask
    }

    #[inline]
    fn set_occupied(&mut self, slot: usize) {
        assert_eq!(self.occupied[slot / 64] & (1u64 << (slot % 64)), 0);
        self.occupied[slot / 64] |= 1u64 << (slot % 64);
        self.occupied_slots += 1;
    }

    #[inline]
    fn set_active_occupied(&mut self, slot: usize) {
        self.active_occupied[slot / 64] |= 1u64 << (slot % 64);
    }

    #[inline]
    fn clear_active_occupied(&mut self, slot: usize) {
        self.active_occupied[slot / 64] &= !(1u64 << (slot % 64));
    }

    fn drain_all_occupied_into(&mut self, expired: &mut Vec<TimeoutEntry>) {
        self.drain_occupied_buckets(|bucket| expired.append(bucket));
    }

    /// Drain occupied slots in `[start, end)` in one bitset pass.
    fn drain_occupied_range_into(
        &mut self,
        start: usize,
        end: usize,
        expired: &mut Vec<TimeoutEntry>,
    ) {
        if start >= end {
            return;
        }

        let start_word = start / 64;
        let end_word = (end - 1) / 64;
        for word_index in start_word..=end_word {
            let word_start = word_index * 64;
            let range_start = start.max(word_start);
            let range_end = end.min(word_start + 64);

            let lo = range_start - word_start;
            let hi = range_end - word_start;
            let mut mask = u64::MAX << lo;
            if hi < 64 {
                mask &= (1u64 << hi) - 1;
            }

            let mut word = self.occupied[word_index] & mask;
            if word == 0 {
                continue;
            }
            self.occupied[word_index] &= !word;
            self.occupied_slots -= word.count_ones() as usize;
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let slot = word_start + bit;
                let bucket = &mut self.buckets[slot];
                assert!(
                    !bucket.is_empty(),
                    "occupied bit set for empty timeout bucket"
                );
                expired.append(bucket);
                word &= word - 1;
            }
        }
    }

    fn compute_min_active_tick(&self) -> Tick {
        let start_slot = self.slot_index(self.current_tick.wrapping_add(1));
        let Some(next_slot) =
            Self::next_set_slot_from(&self.active_occupied, start_slot, self.buckets.len())
        else {
            return Tick::MAX;
        };
        let delta_slots = if next_slot >= start_slot {
            next_slot - start_slot + 1
        } else {
            self.buckets.len() - start_slot + next_slot + 1
        };
        self.current_tick.saturating_add(delta_slots as Tick)
    }

    fn next_set_slot_from(bits: &[u64], start_slot: usize, slots: usize) -> Option<usize> {
        Self::scan_set_range(bits, start_slot, slots)
            .or_else(|| Self::scan_set_range(bits, 0, start_slot))
    }

    fn scan_set_range(bits: &[u64], start: usize, end: usize) -> Option<usize> {
        if start >= end {
            return None;
        }

        let mut bit = start;
        while bit < end {
            let word_index = bit / 64;
            let bit_in_word = bit % 64;
            let mut word = bits[word_index];
            word &= u64::MAX << bit_in_word;

            let word_end = ((word_index + 1) * 64).min(end);
            let bits_in_range = word_end - (word_index * 64);
            if bits_in_range < 64 {
                word &= (1u64 << bits_in_range) - 1;
            }

            if word != 0 {
                let trailing = word.trailing_zeros() as usize;
                return Some(word_index * 64 + trailing);
            }

            bit = (word_index + 1) * 64;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const TICK: Duration = Duration::from_millis(5);

    fn wheel(max_timeout: Duration) -> TimeoutWheel {
        TimeoutWheel::new(max_timeout, TICK, Instant::now())
    }

    fn advance(wheel: &mut TimeoutWheel, now_tick: Tick) -> Vec<TimeoutEntry> {
        let mut expired = Vec::new();
        let bulk_cleared = wheel.advance(now_tick, &mut expired);
        assert!(
            !bulk_cleared,
            "tests expecting partial advance should not hit full-revolution drain"
        );
        expired
    }

    #[test]
    fn test_tick_math_and_target_tick_cases() {
        let tick_nanos = TimeoutWheel::duration_to_nanos_saturating(TICK);
        // 60s / 5ms = 12_000 ticks, plus 1 guard tick => 12_001, next pow2 => 16_384.
        assert_eq!(
            TimeoutWheel::slots_for(Duration::from_secs(60), tick_nanos),
            16_384
        );
        assert_eq!(
            TimeoutWheel::slots_for(Duration::from_nanos(1), tick_nanos),
            2
        );

        let start = Instant::now();
        let mut wheel = TimeoutWheel::new(Duration::from_millis(100), TICK, start);
        for (at, expected) in [(0u64, 0u64), (4, 0), (5, 1), (12, 2)] {
            assert_eq!(wheel.tick_at(start + Duration::from_millis(at)), expected);
        }

        // Past deadline clamps to one tick.
        let past_deadline = start.checked_sub(Duration::from_millis(1)).unwrap_or(start);
        assert_eq!(wheel.target_tick_for_deadline(past_deadline, start), 1);

        // Very far deadline clamps to max_timeout (100ms => 20 ticks at 5ms).
        let far_deadline = start + Duration::from_secs(10);
        assert_eq!(wheel.target_tick_for_deadline(far_deadline, start), 20);

        // Target tick should be computed relative to current_tick after advances.
        assert!(advance(&mut wheel, 7).is_empty());
        let now = start + Duration::from_millis(35);
        let deadline = now + Duration::from_millis(12); // ceil(12/5)=3 ticks.
        assert_eq!(wheel.target_tick_for_deadline(deadline, now), 10);
    }

    #[test]
    fn test_empty_wheel_advance() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 10).is_empty());
        assert_eq!(wheel.current_tick, 10);
        assert_eq!(wheel.timeout_until_next_deadline(), None);
    }

    #[test]
    fn test_schedule_after_advance_via_public_api() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 10).is_empty());

        wheel.schedule(WaiterId::new(1, 0), 12);
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
        assert_eq!(
            wheel.timeout_until_next_deadline(),
            Some(Duration::from_millis(10))
        );

        assert!(advance(&mut wheel, 1).is_empty());
        assert_eq!(
            advance(&mut wheel, 2),
            vec![TimeoutEntry::new(WaiterId::new(1, 0), 2)]
        );
        wheel.remove_active_deadline(2);
        assert_eq!(
            wheel.timeout_until_next_deadline(),
            Some(Duration::from_millis(15))
        );
        assert_eq!(
            advance(&mut wheel, 5),
            vec![TimeoutEntry::new(WaiterId::new(2, 0), 5)]
        );
        wheel.remove_active_deadline(5);
        assert_eq!(wheel.timeout_until_next_deadline(), None);
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
        wheel.remove_active_deadline(2);

        assert!(advance(&mut wheel, 3).is_empty());
        assert_eq!(
            advance(&mut wheel, 4),
            vec![TimeoutEntry::new(WaiterId::new(2, 0), 4)]
        );
        wheel.remove_active_deadline(4);
        assert_eq!(wheel.timeout_until_next_deadline(), None);
    }

    #[test]
    fn test_advance_no_active_fast_path_and_stale_purge() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);
        wheel.remove_active_deadline(2);

        // With no active deadlines, first advance purges stale occupancy and just jumps time.
        let expired = advance(&mut wheel, 10);
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick, 10);
        assert_eq!(wheel.occupied_slots, 0);
        assert_eq!(wheel.timeout_until_next_deadline(), None);

        // Further no-active advances should not rescan stale buckets.
        let expired = advance(&mut wheel, 100);
        assert!(expired.is_empty());
        assert_eq!(wheel.current_tick, 100);
        assert_eq!(wheel.occupied_slots, 0);
    }

    #[test]
    fn test_idle_purge_and_alignment_paths() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);
        wheel.remove_active_deadline(2);
        assert_ne!(wheel.occupied_slots, 0);
        wheel.maybe_purge_idle_stale();
        assert_eq!(wheel.occupied_slots, 0);

        wheel.schedule(WaiterId::new(1, 0), 2);
        let before = wheel.occupied_slots;
        wheel.maybe_purge_idle_stale();
        assert_eq!(wheel.occupied_slots, before);

        let start = Instant::now();
        let mut idle = TimeoutWheel::new(Duration::from_millis(100), TICK, start);
        assert_eq!(idle.current_tick, 0);
        idle.align_idle_to_now(start + Duration::from_millis(50));
        assert_eq!(idle.current_tick, 10); // 50ms / 5ms
        idle.schedule(WaiterId::new(1, 0), 12);
        assert_eq!(idle.min_scheduled_tick, 12);

        let mut active = TimeoutWheel::new(Duration::from_millis(100), TICK, start);
        active.schedule(WaiterId::new(1, 0), 2);
        active.align_idle_to_now(start + Duration::from_millis(50));
        assert_eq!(active.current_tick, 0); // unchanged
    }

    #[test]
    fn test_advance_noop_when_now_tick_not_greater() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);

        assert!(advance(&mut wheel, 0).is_empty());
        assert_eq!(wheel.current_tick, 0);
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
    fn test_timeout_until_next_deadline_wraparound() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 30).is_empty());
        wheel.schedule(WaiterId::new(1, 0), 33);

        // current=30, target=33 -> 3 ticks.
        assert_eq!(
            wheel.timeout_until_next_deadline(),
            Some(Duration::from_millis(15))
        );
    }

    #[test]
    fn test_advance_wraparound_range() {
        let mut wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wheel, 30).is_empty());
        wheel.schedule(WaiterId::new(1, 0), 31);
        wheel.schedule(WaiterId::new(2, 0), 33);

        assert_eq!(
            advance(&mut wheel, 33),
            vec![
                TimeoutEntry::new(WaiterId::new(1, 0), 31),
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
    fn test_advance_large_jump_drains_all_active_deadlines() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 20);
        wheel.schedule(WaiterId::new(2, 0), 5);

        // slots=32 for max_timeout=100ms. Jumping by >= 32 ticks should expire all.
        let mut expired = Vec::new();
        assert!(wheel.advance(40, &mut expired));
        expired.sort_unstable_by_key(|entry| entry.waiter_id.index());
        assert_eq!(
            expired,
            vec![
                TimeoutEntry::new(WaiterId::new(1, 0), 20),
                TimeoutEntry::new(WaiterId::new(2, 0), 5)
            ]
        );
    }

    #[test]
    fn test_full_revolution_then_reschedule() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 5);

        // 32 slots for this wheel; jump by >=32 drains all.
        let mut expired = Vec::new();
        assert!(wheel.advance(40, &mut expired));
        assert_eq!(expired, vec![TimeoutEntry::new(WaiterId::new(1, 0), 5)]);
        assert!(!wheel.has_active_deadlines());
        assert_eq!(wheel.timeout_until_next_deadline(), None);

        wheel.schedule(WaiterId::new(2, 0), 41);
        assert_eq!(
            advance(&mut wheel, 41),
            vec![TimeoutEntry::new(WaiterId::new(2, 0), 41)]
        );
    }

    #[test]
    fn test_advance_clears_prepopulated_output_buffer() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(7, 0), 2);

        let mut expired = vec![TimeoutEntry::new(WaiterId::new(999, 0), 999)];
        wheel.advance(2, &mut expired);
        assert_eq!(expired, vec![TimeoutEntry::new(WaiterId::new(7, 0), 2)]);
    }

    #[test]
    fn test_advance_early_return_preserves_output_buffer() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(7, 0), 10);

        let sentinel = TimeoutEntry::new(WaiterId::new(99, 0), 99);
        let mut expired = vec![sentinel];
        wheel.advance(5, &mut expired); // early return: before min_scheduled_tick
        assert_eq!(expired, vec![sentinel]);
    }

    #[test]
    fn test_min_scheduled_tick_skip_path_preserves_future_entry() {
        let mut wheel = wheel(Duration::from_millis(500));
        wheel.schedule(WaiterId::new(9, 0), 100);

        // now_tick is before earliest scheduled tick, so advance should fast-skip.
        assert!(advance(&mut wheel, 50).is_empty());
        assert_eq!(wheel.current_tick, 50);
        assert_eq!(wheel.min_scheduled_tick, 100);

        // Once we reach the target tick, the entry should still be expired.
        assert_eq!(
            advance(&mut wheel, 100),
            vec![TimeoutEntry::new(WaiterId::new(9, 0), 100)]
        );
    }

    #[test]
    fn test_recompute_min_scheduled_tick_after_partial_drain() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 5);
        wheel.schedule(WaiterId::new(2, 0), 10);

        assert_eq!(
            advance(&mut wheel, 5),
            vec![TimeoutEntry::new(WaiterId::new(1, 0), 5)]
        );
        wheel.remove_active_deadline(5);
        assert_eq!(wheel.min_scheduled_tick, 10);
        assert_eq!(
            wheel.timeout_until_next_deadline(),
            Some(Duration::from_millis(25))
        );
    }

    #[test]
    fn test_remove_non_min_tick_keeps_min_scheduled_tick() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 5);
        wheel.schedule(WaiterId::new(2, 0), 10);

        wheel.remove_active_deadline(10);
        assert_eq!(wheel.min_scheduled_tick, 5);
        assert_eq!(
            wheel.timeout_until_next_deadline(),
            Some(Duration::from_millis(25))
        );
    }

    #[test]
    fn test_reused_slot_stale_entry_preserves_tick_identity() {
        let mut wheel = wheel(Duration::from_millis(100));

        wheel.schedule(WaiterId::new(7, 0), 5);
        wheel.remove_active_deadline(5); // completed early; stale entry stays in bucket until drain
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
    fn test_timeout_entry_preserves_full_target_tick() {
        let tick = (1u64 << 32) + 5;
        let entry = TimeoutEntry::new(WaiterId::new(7, 0), tick);
        assert_eq!(entry.target_tick, tick);
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
    #[should_panic(expected = "max_timeout must be non-zero for timeout wheel")]
    fn test_slots_for_zero_max_timeout_panics() {
        let tick_nanos = TimeoutWheel::duration_to_nanos_saturating(TICK);
        let _ = TimeoutWheel::slots_for(Duration::ZERO, tick_nanos);
    }

    #[test]
    #[should_panic(expected = "timeout wheel tick must be non-zero")]
    fn test_slots_for_zero_tick_panics() {
        let _ = TimeoutWheel::slots_for(Duration::from_millis(1), 0);
    }

    #[test]
    #[should_panic(expected = "timeout wheel tick must be non-zero")]
    fn test_new_zero_tick_panics() {
        let _ = TimeoutWheel::new(Duration::from_millis(100), Duration::ZERO, Instant::now());
    }

    #[test]
    fn test_scan_and_min_helper_cases() {
        let mut bits = vec![0u64; 2];
        bits[0] |= 1u64 << 63;
        bits[1] |= 1u64 << 0;
        bits[1] |= 1u64 << 1;
        assert_eq!(TimeoutWheel::scan_set_range(&bits, 62, 66), Some(63));
        assert_eq!(TimeoutWheel::scan_set_range(&bits, 64, 66), Some(64));
        assert_eq!(TimeoutWheel::scan_set_range(&bits, 65, 66), Some(65));
        assert_eq!(TimeoutWheel::scan_set_range(&bits, 66, 66), None);

        let empty_bits = vec![0u64; 2];
        assert_eq!(TimeoutWheel::scan_set_range(&empty_bits, 1, 65), None);
        assert_eq!(TimeoutWheel::next_set_slot_from(&empty_bits, 64, 128), None);
        let mut wrapped_bits = empty_bits;
        wrapped_bits[0] |= 1u64 << 1;
        assert_eq!(
            TimeoutWheel::next_set_slot_from(&wrapped_bits, 64, 128),
            Some(1)
        );

        let empty_wheel = wheel(Duration::from_millis(100));
        assert_eq!(empty_wheel.compute_min_active_tick(), Tick::MAX);
        let mut wrapped_wheel = wheel(Duration::from_millis(100));
        assert!(advance(&mut wrapped_wheel, 30).is_empty());
        wrapped_wheel.schedule(WaiterId::new(1, 0), 33);
        assert_eq!(wrapped_wheel.compute_min_active_tick(), 33);
    }

    #[test]
    fn test_drain_occupied_range_empty_interval_noop() {
        let mut wheel = wheel(Duration::from_millis(100));
        wheel.schedule(WaiterId::new(1, 0), 2);

        let mut expired = Vec::new();
        wheel.drain_occupied_range_into(7, 7, &mut expired);
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
                wheel.remove_active_deadline(1);
            }));
            assert!(
                err.is_err(),
                "remove_active_deadline should reject active_deadlines underflow"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            wheel.active_deadlines = 1;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.remove_active_deadline(1);
            }));
            assert!(
                err.is_err(),
                "remove_active_deadline should reject missing active slot count"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            wheel.occupied[0] |= 1;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.set_occupied(0);
            }));
            assert!(err.is_err(), "set_occupied should reject duplicate set");
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            wheel.occupied[0] |= 1;
            wheel.occupied_slots = 1;
            let mut expired = Vec::new();
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.drain_occupied_range_into(0, 1, &mut expired);
            }));
            assert!(
                err.is_err(),
                "drain_occupied_range_into should reject empty occupied bucket"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            let invalid_slot = wheel.buckets.len();
            wheel.occupied[invalid_slot / 64] |= 1u64 << (invalid_slot % 64);
            wheel.occupied_slots = 1;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.drain_occupied_buckets(|_| {});
            }));
            assert!(
                err.is_err(),
                "drain_occupied_buckets should reject out-of-range occupied bit"
            );
        }

        {
            let mut wheel = wheel(Duration::from_millis(100));
            let invalid_slot = wheel.active_counts.len();
            wheel.active_occupied[invalid_slot / 64] |= 1u64 << (invalid_slot % 64);
            wheel.active_deadlines = 1;
            let err = catch_unwind(AssertUnwindSafe(|| {
                wheel.clear_all_active();
            }));
            assert!(
                err.is_err(),
                "clear_all_active should reject out-of-range active bit"
            );
        }
    }
}
