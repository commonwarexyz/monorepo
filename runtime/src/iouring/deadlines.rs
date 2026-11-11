//! One driver's request deadlines on the hierarchical timing wheel.
//!
//! The driver keys each request's wheel slot by its waiter's slab index, which
//! stays fixed from admission until the waiter leaves the slab. A slot is
//! resident exactly while that waiter is unfinished, active, and has its
//! deadline installed. Completion and cancellation unlink it at once, before
//! the waiter can leave its slot, and expiry detaches it and returns the slot,
//! so every slot that expiry returns holds an active request, which the
//! driver resolves through its waiters and cancels.
//!
//! The driver alone owns its instance, so it needs no lock, and no peer
//! expires it, since expiry must cancel kernel work on the owner's ring.
//! Times are nanoseconds since the driver's creation, its origin. Network
//! timeouts are at most [`MAX_TIMEOUT`], so a deadline never reaches the end
//! of that range. A slot fires at its deadline rounded up to [`RESOLUTION`],
//! never before it, and one expiry pass spends at most one [`BUDGET`] on
//! firing and refiling slots.
//!
//! [`MAX_TIMEOUT`]: super::runtime::MAX_TIMEOUT

use super::wheel::{BUDGET, InstantExt as _, Wheel};
use std::time::Instant;

/// Resolution of request deadlines in nanoseconds, about a millisecond.
/// Rounding up delays an expiry by less than one tick, which is small next to
/// network timeouts of seconds, and most requests complete long before their
/// deadlines. Deadlines within one tick share a firing time, so a burst of
/// them costs its worker one timed wake.
pub const RESOLUTION: u64 = 1 << 20;

/// Request deadlines of one driver, keyed by waiter slot.
pub struct Deadlines {
    /// One resident slot per active request with an installed deadline.
    wheel: Wheel<RESOLUTION>,
    /// The instant of the driver's creation, from which the wheel, the
    /// bound and expiry times count nanoseconds.
    origin: Instant,
    /// A time never later than the earliest resident's firing time, by
    /// which the next expiry pass must run (see [`Wheel::bound`]), lowered by
    /// insertion and refreshed by an expiry pass that reaches it.
    next: Option<Instant>,
}

impl Deadlines {
    /// Empty deadlines whose time domain starts at `origin`.
    pub fn new(origin: Instant) -> Self {
        Self {
            wheel: Wheel::new(0),
            origin,
            next: None,
        }
    }

    /// Install the deadline of the request in waiter slot `slot`, which must
    /// not be resident.
    pub fn insert(&mut self, slot: u32, deadline: Instant) {
        // The wheel asserts that the slot is not resident, so one waiter
        // installs at most one deadline.
        let nanos = deadline.nanos_since(self.origin);
        let reach = self.wheel.insert(slot, nanos);

        // The bound is the firing time rather than the deadline, so a worker
        // parked on it wakes when the deadline fires, not up to a tick early,
        // or the earlier start of a wheel bucket that the deadline crowds.
        // The firing time is less than a tick after the deadline, so only a
        // deadline at the end of `Instant`'s range lacks one, and that
        // deadline bounds itself.
        let reach = self.origin.after_nanos(reach).unwrap_or(deadline);
        self.next = Some(self.next.map_or(reach, |next| next.min(reach)));
    }

    /// Unlink the deadline that `slot` holds, if any, and return whether it
    /// held one, so completion and cancellation can remove a deadline that
    /// was never installed or that expiry already detached. A resident slot
    /// holds the deadline of the request that occupies it, so the caller
    /// resolves that request's full identity before it removes by slot.
    pub fn remove(&mut self, slot: u32) -> bool {
        if !self.wheel.contains(slot) {
            return false;
        }

        self.wheel.remove(slot);

        // An empty wheel has no firing time, and a nonempty one keeps the
        // bound, possibly early, until the next pass that reaches it.
        if self.wheel.is_empty() {
            self.next = None;
        }

        true
    }

    /// Detach the deadlines due at `now`, spending at most one [`BUDGET`] on
    /// firing and refiling them (see [`Wheel::expire`]), and append their
    /// slots to `fired`. Deadlines left due keep [`Self::next_deadline`] at or
    /// before `now`.
    pub fn expire(&mut self, now: Instant, fired: &mut Vec<u32>) {
        // A bound later than now skips the wheel with one comparison. An
        // early bound left by removals can still cost a pass that fires
        // nothing.
        if self.next.is_none_or(|next| next > now) {
            return;
        }

        let now = now.nanos_since(self.origin);
        let mut budget = BUDGET;
        self.wheel
            .expire(now, &mut budget, &mut |slot| fired.push(slot));

        // Take the wheel's bound, which can be later than one that removals
        // left early. An empty wheel's bound has no instant.
        self.next = self.origin.after_nanos(self.wheel.bound());
    }

    /// A conservative bound on the earliest firing time, or `None` when empty.
    /// New deadlines lower it to their firing time, or to the start of a wheel
    /// bucket that they crowd. Removing a deadline can leave an early bound
    /// until the next expiry pass refreshes it.
    pub const fn next_deadline(&self) -> Option<Instant> {
        self.next
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use commonware_utils::TestRng;
    use rand::RngExt as _;
    use std::{
        collections::{BTreeMap, BTreeSet},
        panic::{AssertUnwindSafe, catch_unwind},
        time::Duration,
    };

    impl Deadlines {
        /// Number of installed deadlines.
        pub(crate) const fn len(&self) -> usize {
            self.wheel.len()
        }

        /// Whether `slot` holds a deadline.
        pub(crate) fn contains(&self, slot: u32) -> bool {
            self.wheel.contains(slot)
        }

        /// The instant at which a deadline installed for `deadline` fires.
        pub(crate) fn fires_at(&self, deadline: Instant) -> Instant {
            let nanos = Wheel::<RESOLUTION>::rounded(deadline.nanos_since(self.origin));
            self.origin.after_nanos(nanos).unwrap()
        }
    }

    /// Expire at `now` and return the fired slots.
    fn expire(deadlines: &mut Deadlines, now: Instant) -> Vec<u32> {
        let mut fired = Vec::new();
        deadlines.expire(now, &mut fired);

        fired
    }

    #[test]
    fn test_cached_bound_survives_removal_and_earlier_insertion() {
        // Two deadlines, the earlier of which is removed.
        let origin = Instant::now();
        let mut deadlines = Deadlines::new(origin);
        let first = origin + Duration::from_secs(10);
        let second = origin + Duration::from_secs(20);
        deadlines.insert(0, first);
        deadlines.insert(1, second);
        deadlines.remove(0);

        // The removed deadline's firing time stays cached, early, until a
        // pass at it refreshes the bound to the survivor's firing time.
        let first = deadlines.fires_at(first);

        assert_eq!(deadlines.next_deadline(), Some(first));
        assert!(expire(&mut deadlines, first - Duration::from_nanos(1)).is_empty());
        assert!(expire(&mut deadlines, first).is_empty());
        assert_eq!(deadlines.next_deadline(), Some(deadlines.fires_at(second)));

        // An earlier insertion between ticks lowers the bound to its firing
        // time, the next tick, and fires then.
        let earlier = first + Duration::from_nanos(1);
        deadlines.insert(0, earlier);
        let fires = deadlines.fires_at(earlier);

        assert_eq!(fires, first + Duration::from_nanos(RESOLUTION));
        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert!(expire(&mut deadlines, fires - Duration::from_nanos(1)).is_empty());
        assert_eq!(expire(&mut deadlines, fires), [0]);

        // Removing the last deadline clears the bound, and one installed
        // after a long idle period caches its own firing time.
        deadlines.remove(1);

        assert_eq!(deadlines.next_deadline(), None);

        let after_idle = origin + Duration::from_secs(3600);

        assert!(expire(&mut deadlines, after_idle).is_empty());

        deadlines.insert(1, after_idle);
        let fires = deadlines.fires_at(after_idle);

        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert_eq!(expire(&mut deadlines, fires), [1]);
    }

    #[test]
    fn test_cached_bound_is_the_firing_time() {
        let origin = Instant::now();
        let mut deadlines = Deadlines::new(origin);

        // A deadline just past a tick fires at the next one, which the bound
        // caches, so a worker parked on the bound wakes once, when it fires.
        let deadline = origin + Duration::from_nanos(RESOLUTION + 1);
        deadlines.insert(0, deadline);
        let fires = origin + Duration::from_nanos(2 * RESOLUTION);

        assert_eq!(deadlines.fires_at(deadline), fires);
        assert_eq!(deadlines.next_deadline(), Some(fires));

        // A later deadline leaves the bound, and one on a tick caches itself.
        deadlines.insert(1, fires + Duration::from_nanos(1));

        assert_eq!(deadlines.next_deadline(), Some(fires));

        let aligned = origin + Duration::from_nanos(RESOLUTION);
        deadlines.insert(2, aligned);

        assert_eq!(deadlines.next_deadline(), Some(aligned));

        // Each pass fires the deadlines due by its time and caches the next
        // firing time, never a deadline.
        assert_eq!(expire(&mut deadlines, aligned), [2]);
        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert_eq!(expire(&mut deadlines, fires), [0]);
        assert_eq!(
            deadlines.next_deadline(),
            Some(origin + Duration::from_nanos(3 * RESOLUTION))
        );
    }

    #[test]
    fn test_crowded_bucket_is_refiled_before_its_firing_time() {
        // Eight budgets of requests share one deadline an hour ahead, and
        // with it one high wheel bucket, which they crowd.
        let origin = Instant::now();
        let mut deadlines = Deadlines::new(origin);
        let deadline = origin + Duration::from_secs(3600);

        for slot in 0..8 * BUDGET {
            deadlines.insert(slot, deadline);
        }

        // The bound falls to the bucket's start, and passes at the bounds
        // that follow refile the bucket down the levels and fire nothing.
        let fires = deadlines.fires_at(deadline);

        assert!(deadlines.next_deadline().unwrap() < fires);

        while let Some(bound) = deadlines.next_deadline().filter(|bound| *bound < fires) {
            assert!(expire(&mut deadlines, bound).is_empty());
        }

        // So the first pass at the firing time spends its whole budget on
        // firing.
        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert_eq!(expire(&mut deadlines, fires).len(), BUDGET as usize);
    }

    #[test]
    fn test_deadlines_fire_rounded_up_and_never_early() {
        // Deadlines on and around tick boundaries fire less than a tick after
        // them, and the bound covers the earliest.
        let origin = Instant::now();
        let mut deadlines = Deadlines::new(origin);
        let offsets = [
            1,
            RESOLUTION - 1,
            RESOLUTION,
            RESOLUTION + 1,
            59_999_999_999,
        ];

        for (slot, offset) in offsets.iter().enumerate() {
            let deadline = origin + Duration::from_nanos(*offset);
            deadlines.insert(slot as u32, deadline);
            let fires = deadlines.fires_at(deadline);

            assert!(fires >= deadline);
            assert!(fires < deadline + Duration::from_nanos(RESOLUTION));
        }

        assert!(deadlines.next_deadline().unwrap() <= origin + Duration::from_nanos(RESOLUTION));

        // Each fires at its firing time, not one nanosecond earlier.
        let mut fired = Vec::new();

        for (slot, offset) in offsets.iter().enumerate() {
            let fires = deadlines.fires_at(origin + Duration::from_nanos(*offset));
            let before = expire(&mut deadlines, fires - Duration::from_nanos(1));

            assert!(!before.contains(&(slot as u32)), "fired early");

            fired.extend(before);
            fired.extend(expire(&mut deadlines, fires));

            assert!(fired.contains(&(slot as u32)), "fired late");
        }

        // Each fired once, leaving nothing installed.
        assert_eq!(fired.len(), offsets.len());
        assert_eq!(deadlines.len(), 0);
        assert_eq!(deadlines.next_deadline(), None);
    }

    #[test]
    fn test_removal_is_exact_and_once() {
        // Two requests share one deadline.
        let origin = Instant::now();
        let mut deadlines = Deadlines::new(origin);
        let deadline = origin + Duration::from_secs(10);
        deadlines.insert(0, deadline);
        deadlines.insert(1, deadline);

        // A second insertion panics before changing anything, while a second
        // removal and a slot that never held a deadline remove nothing.
        assert!(catch_unwind(AssertUnwindSafe(|| deadlines.insert(0, deadline))).is_err());
        assert!(!deadlines.remove(7));
        assert_eq!(deadlines.len(), 2);
        assert!(deadlines.remove(0));
        assert!(!deadlines.remove(0));
        assert_eq!(deadlines.len(), 1);

        // The reused slot holds its new deadline, and the removed one never
        // fires.
        deadlines.insert(0, deadline + Duration::from_secs(1));

        assert!(deadlines.contains(0));

        let fires = deadlines.fires_at(deadline);
        let fired = expire(&mut deadlines, fires);

        assert_eq!(fired, [1]);

        let later = deadline + Duration::from_secs(1);
        let fires = deadlines.fires_at(later);
        let fired = expire(&mut deadlines, fires);

        assert_eq!(fired, [0]);
        assert_eq!(deadlines.next_deadline(), None);
    }

    #[test]
    fn test_times_saturate_at_both_ends() {
        let origin = Instant::now() + Duration::from_secs(1);
        let mut deadlines = Deadlines::new(origin);

        // A deadline before the origin is due at once.
        deadlines.insert(0, origin - Duration::from_millis(1));

        assert!(deadlines.next_deadline().unwrap() <= origin);
        assert_eq!(expire(&mut deadlines, origin), [0]);

        // A 30 year deadline, the configured maximum, is far from the end.
        let far = origin + Duration::from_secs(30 * 365 * 24 * 60 * 60);
        deadlines.insert(1, far);
        let fires = deadlines.fires_at(far);

        assert!(fires >= far && fires < far + Duration::from_nanos(RESOLUTION));
        assert!(deadlines.next_deadline().unwrap() <= fires);
        assert!(expire(&mut deadlines, far - Duration::from_secs(1)).is_empty());
        assert_eq!(expire(&mut deadlines, fires), [1]);
    }

    /// Compare installed slots and rounded times with an ordered model,
    /// including early completion, cancellation, reuse and long idle jumps.
    #[test]
    fn test_randomized_deadlines_match_an_ordered_model() {
        /// Waiter slots the model reuses.
        const SLOTS: u32 = 128;

        for seed in 0..8 {
            // The model: each live slot's firing time, and the same ordered
            // by firing time.
            let mut rng = TestRng::new(seed);
            let origin = Instant::now();
            let mut deadlines = Deadlines::new(origin);
            let mut live = BTreeMap::<u32, u64>::new();
            let mut ordered = BTreeSet::<(u64, u32)>::new();
            let mut fired = Vec::new();
            let mut now = 0u64;

            for step in 0..20_000 {
                match rng.random_range(0..8) {
                    // Install a past, current, near, or far deadline in a free
                    // slot.
                    0..=2 => {
                        let slot = rng.random_range(0..SLOTS);

                        if live.contains_key(&slot) {
                            continue;
                        }

                        let offset = match rng.random_range(0..5) {
                            0 => now.saturating_sub(rng.random_range(0..=10 * RESOLUTION)),
                            1 => now,
                            2 => now + rng.random_range(0..=1_000 * RESOLUTION),
                            _ => {
                                now + rng.random_range(0..=30 * 365 * 24 * 3600 * 1_000_000_000u64)
                            }
                        };

                        // Independent rounding, without calling the wheel.
                        let firing = offset.div_ceil(RESOLUTION) * RESOLUTION;
                        deadlines.insert(slot, origin + Duration::from_nanos(offset));
                        live.insert(slot, firing);
                        ordered.insert((firing, slot));
                    }
                    // Remove a random live deadline.
                    3 | 4 => {
                        if live.is_empty() {
                            continue;
                        }

                        let pick = rng.random_range(0..live.len());
                        let (&slot, &firing) = live.iter().nth(pick).unwrap();

                        // Cancellation and terminal completion both eagerly
                        // unlink their installed deadline.
                        assert!(deadlines.remove(slot));

                        live.remove(&slot);
                        ordered.remove(&(firing, slot));
                    }
                    // Advance time, sometimes by a long idle period, and
                    // expire until the bound is later, as the driver would.
                    _ => {
                        now += if rng.random_range(0..10) == 0 {
                            rng.random_range(0..=24 * 3600 * 1_000_000_000u64)
                        } else {
                            rng.random_range(0..=10_000 * RESOLUTION)
                        };

                        let at = origin + Duration::from_nanos(now);
                        let mut passes = 0;

                        while deadlines.next_deadline().is_some_and(|bound| bound <= at) {
                            passes += 1;

                            assert!(
                                passes <= 10 * SLOTS,
                                "seed {seed}, step {step}: stalled expiry"
                            );

                            deadlines.expire(at, &mut fired);

                            for slot in fired.drain(..) {
                                let firing = live.remove(&slot).expect("stale or duplicate expiry");

                                assert!(firing <= now, "seed {seed}, step {step}: early expiry");
                                assert!(ordered.remove(&(firing, slot)));
                            }
                        }

                        assert!(
                            ordered.first().is_none_or(|(firing, _)| *firing > now),
                            "seed {seed}, step {step}: due deadline survived"
                        );
                    }
                }

                // After every step, the same slots are installed and the
                // bound is never after the earliest firing time.
                assert_eq!(deadlines.len(), live.len(), "seed {seed}, step {step}");

                for slot in 0..SLOTS {
                    assert_eq!(
                        deadlines.contains(slot),
                        live.contains_key(&slot),
                        "seed {seed}, step {step}"
                    );
                }

                match ordered.first() {
                    Some((firing, _)) => assert!(
                        deadlines.next_deadline().unwrap()
                            <= origin + Duration::from_nanos(*firing),
                        "seed {seed}, step {step}: late bound"
                    ),
                    None => assert_eq!(deadlines.next_deadline(), None),
                }
            }
        }
    }
}
