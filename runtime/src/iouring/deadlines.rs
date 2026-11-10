//! One driver's request deadlines on the hierarchical timing wheel.
//!
//! The driver keys each request's wheel slot by its waiter's slab index, which
//! stays fixed from admission until the waiter leaves the slab, and records
//! the waiter's generation beside it. A slot is resident exactly while that
//! waiter is unfinished, active, and has its deadline installed. Completion
//! and cancellation unlink it at once by full identity, and expiry detaches it
//! and returns that identity, so every identity that expiry returns belongs to
//! an active request, which the driver cancels.
//!
//! The driver alone owns its instance, so it needs no lock, and no peer
//! expires it, since expiry must cancel kernel work on the owner's ring.
//! Times are nanoseconds since the driver's creation, its epoch. Network
//! timeouts are at most [`MAX_TIMEOUT`], so a deadline never reaches the end
//! of that range. A slot fires at its deadline rounded up to [`RESOLUTION`],
//! never before it, and one expiry pass spends at most one [`BUDGET`] on
//! firing and refiling slots.
//!
//! [`MAX_TIMEOUT`]: super::runtime::MAX_TIMEOUT

use super::{
    waiter::WaiterId,
    wheel::{BUDGET, InstantExt as _, Wheel},
};
use std::time::Instant;

/// Resolution of request deadlines in nanoseconds, about a millisecond.
/// Requests usually complete long before their deadlines, so coarse ticks
/// cost little precision, and the expiries of a burst share a few passes.
pub const RESOLUTION: u64 = 1 << 20;

/// Request deadlines of one driver, keyed by waiter slot.
pub struct Deadlines {
    /// One resident slot per active request with an installed deadline.
    wheel: Wheel<RESOLUTION>,
    /// Generation of the waiter whose deadline each slot holds, meaningful
    /// while the slot is resident. The wheel keys slots by waiter index alone,
    /// which the waiter slab reuses for later waiters, so the generation
    /// tells the waiter that installed a deadline from an identity whose
    /// waiter already left: removal unlinks a deadline only for the identity
    /// that installed it, and expiry returns that full identity.
    generations: Vec<u64>,
    /// Origin of the wheel's nanosecond time domain.
    epoch: Instant,
    /// Identities fired by the latest pass, kept for their allocation.
    fired: Vec<WaiterId>,
    /// A time never later than the earliest resident's firing time, by
    /// which the next expiry pass must run (see [`Wheel::bound`]), lowered by
    /// insertion and refreshed by an expiry pass that reaches it.
    next: Option<Instant>,
}

impl Deadlines {
    /// Empty deadlines whose time domain starts at `epoch`.
    pub fn new(epoch: Instant) -> Self {
        Self {
            wheel: Wheel::new(0),
            generations: Vec::new(),
            epoch,
            fired: Vec::new(),
            next: None,
        }
    }

    /// Install the deadline of the waiter `id`, whose slot must not be resident.
    pub fn insert(&mut self, id: WaiterId, deadline: Instant) {
        // The wheel asserts that the slot is not resident, so one waiter
        // installs at most one deadline.
        let slot = id.0.index;
        let nanos = deadline.nanos_since(self.epoch);
        let reach = self.wheel.insert(slot, nanos);

        // The bound is the firing time rather than the deadline, so a worker
        // parked on it wakes when the deadline fires, not up to a tick early,
        // or the earlier start of a wheel bucket that the deadline crowds.
        // The firing time is less than a tick after the deadline, so only a
        // deadline at the end of `Instant`'s range lacks one, and that
        // deadline bounds itself.
        let reach = self.epoch.after_nanos(reach).unwrap_or(deadline);
        self.next = Some(self.next.map_or(reach, |next| next.min(reach)));

        // Record the generation that a later removal must match. The vector
        // grows to the highest waiter index and is never shrunk, like the
        // wheel's links.
        let index = slot as usize;
        if index >= self.generations.len() {
            self.generations.resize(index + 1, 0);
        }
        self.generations[index] = id.0.generation;
    }

    /// Unlink the deadline of the waiter `id` if its slot holds it, and return
    /// whether it did. A slot holding no deadline, or another generation's, is
    /// left alone, so completion and cancellation can remove a deadline that
    /// was never installed or that expiry already detached, and a stale
    /// identity cannot unlink another request's deadline.
    pub fn remove(&mut self, id: WaiterId) -> bool {
        // Residency alone is not enough: a later waiter in the same slot may
        // hold its own deadline there.
        let slot = id.0.index;
        let held = self.wheel.contains(slot)
            && self.generations.get(slot as usize) == Some(&id.0.generation);
        if !held {
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
    /// firing and refiling them (see [`Wheel::expire`]), and return the
    /// identities that installed them. Deadlines left due keep
    /// [`Self::next_deadline`] at or before `now`. Hand the vector back with
    /// [`Self::recycle`].
    pub fn expire(&mut self, now: Instant) -> Vec<WaiterId> {
        let mut fired = std::mem::take(&mut self.fired);

        // A bound later than now skips the wheel with one comparison. An
        // early bound left by removals can still cost a pass that fires
        // nothing.
        if self.next.is_none_or(|next| next > now) {
            return fired;
        }

        // Each fired slot leaves the wheel, and its recorded generation
        // rebuilds the identity that installed it.
        let now = now.nanos_since(self.epoch);
        let mut budget = BUDGET;
        let generations = &self.generations;
        self.wheel.expire(now, &mut budget, &mut |index| {
            fired.push(WaiterId(super::slab::Id {
                index,
                generation: generations[index as usize],
            }));
        });

        // Take the wheel's bound, which can be later than one that removals
        // left early. An empty wheel's bound has no instant.
        self.next = self.epoch.after_nanos(self.wheel.bound());
        fired
    }

    /// Return the vector of an expiry pass for reuse.
    pub fn recycle(&mut self, mut fired: Vec<WaiterId>) {
        fired.clear();
        self.fired = fired;
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
    use crate::iouring::slab::Id;
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

        /// The identity whose deadline `slot` holds, if any.
        pub(crate) fn holder(&self, slot: u32) -> Option<WaiterId> {
            self.wheel.contains(slot).then(|| {
                WaiterId(Id {
                    index: slot,
                    generation: self.generations[slot as usize],
                })
            })
        }

        /// The instant at which a deadline installed for `deadline` fires.
        pub(crate) fn fires_at(&self, deadline: Instant) -> Instant {
            let nanos = Wheel::<RESOLUTION>::rounded(deadline.nanos_since(self.epoch));
            self.epoch.after_nanos(nanos).unwrap()
        }
    }

    /// The identity of `generation` at `index`.
    const fn id(index: u32, generation: u64) -> WaiterId {
        WaiterId(Id { index, generation })
    }

    /// Expire at `now` and return the fired identities.
    fn expire(deadlines: &mut Deadlines, now: Instant) -> Vec<WaiterId> {
        let fired = deadlines.expire(now);
        let result = fired.clone();
        deadlines.recycle(fired);
        result
    }

    #[test]
    fn test_cached_bound_survives_removal_and_earlier_insertion() {
        // Two deadlines, the earlier of which is removed.
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let first = epoch + Duration::from_secs(10);
        let second = epoch + Duration::from_secs(20);
        deadlines.insert(id(0, 0), first);
        deadlines.insert(id(1, 0), second);
        deadlines.remove(id(0, 0));

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
        deadlines.insert(id(0, 1), earlier);
        let fires = deadlines.fires_at(earlier);
        assert_eq!(fires, first + Duration::from_nanos(RESOLUTION));
        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert!(expire(&mut deadlines, fires - Duration::from_nanos(1)).is_empty());
        assert_eq!(expire(&mut deadlines, fires), [id(0, 1)]);

        // Removing the last deadline clears the bound, and one installed
        // after a long idle period caches its own firing time.
        deadlines.remove(id(1, 0));
        assert_eq!(deadlines.next_deadline(), None);
        let after_idle = epoch + Duration::from_secs(3600);
        assert!(expire(&mut deadlines, after_idle).is_empty());
        deadlines.insert(id(1, 1), after_idle);
        let fires = deadlines.fires_at(after_idle);
        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert_eq!(expire(&mut deadlines, fires), [id(1, 1)]);
    }

    #[test]
    fn test_cached_bound_is_the_firing_time() {
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);

        // A deadline just past a tick fires at the next one, which the bound
        // caches, so a worker parked on the bound wakes once, when it fires.
        let deadline = epoch + Duration::from_nanos(RESOLUTION + 1);
        deadlines.insert(id(0, 0), deadline);
        let fires = epoch + Duration::from_nanos(2 * RESOLUTION);
        assert_eq!(deadlines.fires_at(deadline), fires);
        assert_eq!(deadlines.next_deadline(), Some(fires));

        // A later deadline leaves the bound, and one on a tick caches itself.
        deadlines.insert(id(1, 0), fires + Duration::from_nanos(1));
        assert_eq!(deadlines.next_deadline(), Some(fires));
        let aligned = epoch + Duration::from_nanos(RESOLUTION);
        deadlines.insert(id(2, 0), aligned);
        assert_eq!(deadlines.next_deadline(), Some(aligned));

        // Each pass fires the deadlines due by its time and caches the next
        // firing time, never a deadline.
        assert_eq!(expire(&mut deadlines, aligned), [id(2, 0)]);
        assert_eq!(deadlines.next_deadline(), Some(fires));
        assert_eq!(expire(&mut deadlines, fires), [id(0, 0)]);
        assert_eq!(
            deadlines.next_deadline(),
            Some(epoch + Duration::from_nanos(3 * RESOLUTION))
        );
    }

    #[test]
    fn test_crowded_bucket_is_refiled_before_its_firing_time() {
        // Eight budgets of requests share one deadline an hour ahead, and
        // with it one high wheel bucket, which they crowd.
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let deadline = epoch + Duration::from_secs(3600);
        for slot in 0..8 * BUDGET {
            deadlines.insert(id(slot, 0), deadline);
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
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let offsets = [
            1,
            RESOLUTION - 1,
            RESOLUTION,
            RESOLUTION + 1,
            59_999_999_999,
        ];
        for (slot, offset) in offsets.iter().enumerate() {
            let deadline = epoch + Duration::from_nanos(*offset);
            deadlines.insert(id(slot as u32, 0), deadline);
            let fires = deadlines.fires_at(deadline);
            assert!(fires >= deadline);
            assert!(fires < deadline + Duration::from_nanos(RESOLUTION));
        }
        assert!(deadlines.next_deadline().unwrap() <= epoch + Duration::from_nanos(RESOLUTION));

        // Each fires at its firing time, not one nanosecond earlier.
        let mut fired = Vec::new();
        for (slot, offset) in offsets.iter().enumerate() {
            let fires = deadlines.fires_at(epoch + Duration::from_nanos(*offset));
            let before = expire(&mut deadlines, fires - Duration::from_nanos(1));
            assert!(!before.contains(&id(slot as u32, 0)), "fired early");
            fired.extend(before);
            fired.extend(expire(&mut deadlines, fires));
            assert!(fired.contains(&id(slot as u32, 0)), "fired late");
        }

        // Each fired once, leaving nothing installed.
        assert_eq!(fired.len(), offsets.len());
        assert_eq!(deadlines.len(), 0);
        assert_eq!(deadlines.next_deadline(), None);
    }

    #[test]
    fn test_removal_is_exact_and_once() {
        // Two requests share one deadline.
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let deadline = epoch + Duration::from_secs(10);
        deadlines.insert(id(0, 0), deadline);
        deadlines.insert(id(1, 0), deadline);

        // A second insertion panics before changing anything, while a stale
        // generation, a second removal, and a slot that never held a deadline
        // remove nothing.
        assert!(catch_unwind(AssertUnwindSafe(|| deadlines.insert(id(0, 1), deadline))).is_err());
        assert!(!deadlines.remove(id(0, 1)));
        assert!(!deadlines.remove(id(7, 0)));
        assert_eq!(deadlines.len(), 2);
        assert!(deadlines.remove(id(0, 0)));
        assert!(!deadlines.remove(id(0, 0)));
        assert_eq!(deadlines.len(), 1);

        // The reused slot reports its new generation, and the removed deadline
        // never fires.
        deadlines.insert(id(0, 1), deadline + Duration::from_secs(1));
        assert_eq!(deadlines.holder(0), Some(id(0, 1)));
        let fires = deadlines.fires_at(deadline);
        let fired = expire(&mut deadlines, fires);
        assert_eq!(fired, [id(1, 0)]);
        let later = deadline + Duration::from_secs(1);
        let fires = deadlines.fires_at(later);
        let fired = expire(&mut deadlines, fires);
        assert_eq!(fired, [id(0, 1)]);
        assert_eq!(deadlines.next_deadline(), None);
    }

    #[test]
    fn test_budget_leaves_a_due_backlog_that_drains() {
        // More than three budgets of requests share one deadline.
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let deadline = epoch + Duration::from_millis(100);
        let count = 3 * BUDGET + 7;
        for slot in 0..count {
            deadlines.insert(id(slot, 0), deadline);
        }

        // Passes at one time fire at most one budget each, and the bound
        // stays at or before that time while some remain.
        let now = deadlines.fires_at(deadline);
        let mut passes = 0;
        let mut total = 0;
        while deadlines.len() > 0 {
            let fired = expire(&mut deadlines, now);
            assert!(fired.len() <= BUDGET as usize);
            total += fired.len();
            passes += 1;
            if deadlines.len() > 0 {
                assert!(deadlines.next_deadline().unwrap() <= now);
            }
        }

        // All of them fired within a few passes.
        assert_eq!(total, count as usize);
        assert!((4..=5).contains(&passes), "{passes} passes");
    }

    #[test]
    fn test_times_saturate_at_both_ends() {
        let epoch = Instant::now() + Duration::from_secs(1);
        let mut deadlines = Deadlines::new(epoch);

        // A deadline before the epoch is due at once.
        deadlines.insert(id(0, 0), epoch - Duration::from_millis(1));
        assert!(deadlines.next_deadline().unwrap() <= epoch);
        assert_eq!(expire(&mut deadlines, epoch), [id(0, 0)]);

        // A 30 year deadline, the configured maximum, is far from the end.
        let far = epoch + Duration::from_secs(30 * 365 * 24 * 60 * 60);
        deadlines.insert(id(1, 0), far);
        let fires = deadlines.fires_at(far);
        assert!(fires >= far && fires < far + Duration::from_nanos(RESOLUTION));
        assert!(deadlines.next_deadline().unwrap() <= fires);
        assert!(expire(&mut deadlines, far - Duration::from_secs(1)).is_empty());
        assert_eq!(expire(&mut deadlines, fires), [id(1, 0)]);
    }

    /// Compare request identities and rounded times with an ordered model,
    /// including early completion, cancellation, reuse and long idle jumps.
    #[test]
    fn test_randomized_deadlines_match_an_ordered_model() {
        /// Waiter slots the model reuses.
        const SLOTS: u32 = 128;
        for seed in 0..8 {
            // The model: each live slot's generation and firing time, and the
            // same ordered by firing time.
            let mut rng = TestRng::new(seed);
            let epoch = Instant::now();
            let mut deadlines = Deadlines::new(epoch);
            let mut generations = [0; SLOTS as usize];
            let mut live = BTreeMap::<u32, (u64, u64)>::new();
            let mut ordered = BTreeSet::<(u64, u32, u64)>::new();
            let mut now = 0u64;
            for step in 0..20_000 {
                match rng.random_range(0..8) {
                    // Install a past, current, near, or far deadline in a free
                    // slot under a new generation.
                    0..=2 => {
                        let slot = rng.random_range(0..SLOTS);
                        if live.contains_key(&slot) {
                            continue;
                        }
                        generations[slot as usize] += 1;
                        let generation = generations[slot as usize];
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
                        deadlines
                            .insert(id(slot, generation), epoch + Duration::from_nanos(offset));
                        live.insert(slot, (generation, firing));
                        ordered.insert((firing, slot, generation));
                    }
                    // Remove a random live deadline.
                    3 | 4 => {
                        if live.is_empty() {
                            continue;
                        }
                        let pick = rng.random_range(0..live.len());
                        let (&slot, &(generation, firing)) = live.iter().nth(pick).unwrap();
                        // Cancellation and terminal completion both eagerly
                        // unlink their installed deadline by full identity.
                        deadlines.remove(id(slot, generation));
                        live.remove(&slot);
                        ordered.remove(&(firing, slot, generation));
                    }
                    // Advance time, sometimes by a long idle period, and
                    // expire until the bound is later, as the driver would.
                    _ => {
                        now += if rng.random_range(0..10) == 0 {
                            rng.random_range(0..=24 * 3600 * 1_000_000_000u64)
                        } else {
                            rng.random_range(0..=10_000 * RESOLUTION)
                        };
                        let at = epoch + Duration::from_nanos(now);
                        let mut passes = 0;
                        while deadlines.next_deadline().is_some_and(|bound| bound <= at) {
                            passes += 1;
                            assert!(
                                passes <= 10 * SLOTS,
                                "seed {seed}, step {step}: stalled expiry"
                            );
                            let fired = deadlines.expire(at);
                            for current in &fired {
                                let (generation, firing) = live
                                    .remove(&current.0.index)
                                    .expect("stale or duplicate expiry");
                                assert_eq!(
                                    current.0.generation, generation,
                                    "seed {seed}, step {step}"
                                );
                                assert!(firing <= now, "seed {seed}, step {step}: early expiry");
                                assert!(ordered.remove(&(firing, current.0.index, generation)));
                            }
                            deadlines.recycle(fired);
                        }
                        assert!(
                            ordered.first().is_none_or(|(firing, _, _)| *firing > now),
                            "seed {seed}, step {step}: due deadline survived"
                        );
                    }
                }

                // After every step, the same identities are installed and the
                // bound is never after the earliest firing time.
                assert_eq!(deadlines.len(), live.len(), "seed {seed}, step {step}");
                for slot in 0..SLOTS {
                    assert_eq!(
                        deadlines.holder(slot),
                        live.get(&slot).map(|(generation, _)| id(slot, *generation)),
                        "seed {seed}, step {step}"
                    );
                }
                match ordered.first() {
                    Some((firing, _, _)) => assert!(
                        deadlines.next_deadline().unwrap() <= epoch + Duration::from_nanos(*firing),
                        "seed {seed}, step {step}: late bound"
                    ),
                    None => assert_eq!(deadlines.next_deadline(), None),
                }
            }
        }
    }
}
