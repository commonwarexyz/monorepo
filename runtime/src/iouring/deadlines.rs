//! One driver's request deadlines on the hierarchical timing wheel.
//!
//! The driver keys each request's node by its waiter's slab index, which stays
//! fixed from admission until the waiter leaves the slab, and records the
//! waiter's generation beside it. A node is resident exactly while that
//! waiter is unfinished, active, and has its deadline installed. Completion
//! and cancellation unlink it at once by full identity, and expiry detaches it
//! and returns that identity, so the driver cancels the one request holding
//! it. Nothing stale stays behind for later filtering.
//!
//! The driver alone owns its instance, so it needs no lock, and no peer
//! expires it, since expiry must cancel kernel work on the owner's ring.
//! Times are nanoseconds since the driver's creation. A node fires at its
//! deadline rounded up to [`RES`], never before it, and one expiry pass fires
//! or refiles at most [`BUDGET`] nodes.

use super::{
    waiter::WaiterId,
    wheel::{BUDGET, Wheel},
};
use std::time::{Duration, Instant};

/// Resolution of request deadlines in nanoseconds, about a millisecond.
/// Requests usually complete long before their deadline, so this resolution
/// lets the expiries of a burst share a few passes.
pub const RES: u64 = 1 << 20;

/// Request deadlines of one driver, keyed by waiter slot.
pub struct Deadlines {
    /// One resident node per active request with an installed deadline.
    wheel: Wheel<RES>,
    /// Generation of the waiter whose node each slot holds, meaningful while
    /// the slot is resident.
    generations: Vec<u64>,
    /// Origin of the wheel's nanosecond time domain.
    epoch: Instant,
    /// Identities fired by the latest pass, kept for their allocation.
    fired: Vec<WaiterId>,
    /// Conservative firing bound, refreshed only when it is reached.
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

    /// Nanoseconds of `instant` since the epoch, saturating at both ends.
    /// Configured timeouts are at most 30 years, so a deadline never reaches
    /// the upper end.
    fn nanos(&self, instant: Instant) -> u64 {
        let since = instant.saturating_duration_since(self.epoch);
        u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
    }

    /// Install the deadline of the waiter `id`, whose slot must not be resident.
    pub fn insert(&mut self, id: WaiterId, deadline: Instant) {
        let slot = id.0.index;
        self.wheel.insert(slot, self.nanos(deadline));
        self.next = Some(self.next.map_or(deadline, |next| next.min(deadline)));
        let index = slot as usize;
        if index >= self.generations.len() {
            self.generations.resize(index + 1, 0);
        }
        self.generations[index] = id.0.generation;
    }

    /// Unlink the deadline of the waiter `id`. Panics before any change if its
    /// slot is not resident or holds another generation's deadline.
    pub fn remove(&mut self, id: WaiterId) {
        let slot = id.0.index;
        assert!(
            self.generations[slot as usize] == id.0.generation,
            "request deadline not resident"
        );
        self.wheel.remove(slot);
        if self.wheel.is_empty() {
            self.next = None;
        }
    }

    /// Detach the deadlines due at `now`, at most one budget of them fired or
    /// refiled, and return the identities that installed them. Deadlines left
    /// due keep [`Self::next_deadline`] at or before `now`. Hand the vector
    /// back with [`Self::recycle`].
    pub fn expire(&mut self, now: Instant) -> Vec<WaiterId> {
        let mut fired = std::mem::take(&mut self.fired);
        if self.next.is_none_or(|next| next > now) {
            return fired;
        }
        let now = self.nanos(now);
        let mut budget = BUDGET;
        let generations = &self.generations;
        self.wheel.expire(now, &mut budget, &mut |index| {
            fired.push(WaiterId(super::slab::Id {
                index,
                generation: generations[index as usize],
            }));
        });
        let bound = self.wheel.bound();
        self.next = (bound != u64::MAX)
            .then(|| self.epoch.checked_add(Duration::from_nanos(bound)))
            .flatten();
        fired
    }

    /// Return the vector of an expiry pass for reuse.
    pub fn recycle(&mut self, mut fired: Vec<WaiterId>) {
        fired.clear();
        self.fired = fired;
    }

    /// A conservative bound on the earliest firing time, or `None` when empty.
    /// New deadlines use their unrounded time. Removing a deadline can leave
    /// an early bound until the next expiry pass refreshes it.
    pub const fn next_deadline(&self) -> Option<Instant> {
        self.next
    }

    /// Number of installed deadlines.
    #[cfg(test)]
    pub const fn len(&self) -> usize {
        self.wheel.len()
    }

    /// The identity whose deadline `slot` holds, if any.
    #[cfg(test)]
    pub fn holder(&self, slot: u32) -> Option<WaiterId> {
        self.wheel.contains(slot).then(|| {
            WaiterId(super::slab::Id {
                index: slot,
                generation: self.generations[slot as usize],
            })
        })
    }

    /// The instant at which a deadline installed for `deadline` fires.
    #[cfg(test)]
    pub fn fires_at(&self, deadline: Instant) -> Instant {
        self.epoch + Duration::from_nanos(Wheel::<RES>::rounded(self.nanos(deadline)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iouring::slab::Id;
    use commonware_utils::TestRng;
    use rand::RngExt as _;
    use std::{
        collections::{BTreeMap, BTreeSet},
        panic::{AssertUnwindSafe, catch_unwind},
    };

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
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let first = epoch + Duration::from_secs(10);
        let second = epoch + Duration::from_secs(20);
        deadlines.insert(id(0, 0), first);
        deadlines.insert(id(1, 0), second);
        deadlines.remove(id(0, 0));
        let first = deadlines.fires_at(first);
        assert!(deadlines.next_deadline().unwrap() <= first);
        assert!(expire(&mut deadlines, first - Duration::from_nanos(1)).is_empty());
        assert!(expire(&mut deadlines, first).is_empty());
        assert_eq!(deadlines.next_deadline(), Some(deadlines.fires_at(second)));
        let earlier = first + Duration::from_nanos(RES);
        deadlines.insert(id(0, 1), earlier);
        assert_eq!(deadlines.next_deadline(), Some(earlier));
        assert_eq!(expire(&mut deadlines, earlier), [id(0, 1)]);
        deadlines.remove(id(1, 0));
        assert_eq!(deadlines.next_deadline(), None);
        let after_idle = epoch + Duration::from_secs(3600);
        assert!(expire(&mut deadlines, after_idle).is_empty());
        deadlines.insert(id(1, 1), after_idle);
        let fires = deadlines.fires_at(after_idle);
        assert_eq!(expire(&mut deadlines, fires), [id(1, 1)]);
    }

    #[test]
    fn test_deadlines_fire_rounded_up_and_never_early() {
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let offsets = [1, RES - 1, RES, RES + 1, 59_999_999_999];
        for (slot, offset) in offsets.iter().enumerate() {
            let deadline = epoch + Duration::from_nanos(*offset);
            deadlines.insert(id(slot as u32, 0), deadline);
            let fires = deadlines.fires_at(deadline);
            assert!(fires >= deadline);
            assert!(fires < deadline + Duration::from_nanos(RES));
        }
        assert!(deadlines.next_deadline().unwrap() <= epoch + Duration::from_nanos(RES));
        let mut fired = Vec::new();
        for (slot, offset) in offsets.iter().enumerate() {
            let fires = deadlines.fires_at(epoch + Duration::from_nanos(*offset));
            let before = expire(&mut deadlines, fires - Duration::from_nanos(1));
            assert!(!before.contains(&id(slot as u32, 0)), "fired early");
            fired.extend(before);
            fired.extend(expire(&mut deadlines, fires));
            assert!(fired.contains(&id(slot as u32, 0)), "fired late");
        }
        assert_eq!(fired.len(), offsets.len());
        assert_eq!(deadlines.len(), 0);
        assert_eq!(deadlines.next_deadline(), None);
    }

    #[test]
    fn test_removal_is_exact_and_once() {
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let deadline = epoch + Duration::from_secs(10);
        deadlines.insert(id(0, 0), deadline);
        deadlines.insert(id(1, 0), deadline);

        // A second insertion, a stale generation, and a second removal panic
        // before changing anything.
        assert!(catch_unwind(AssertUnwindSafe(|| deadlines.insert(id(0, 1), deadline))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| deadlines.remove(id(0, 1)))).is_err());
        assert_eq!(deadlines.len(), 2);
        deadlines.remove(id(0, 0));
        assert!(catch_unwind(AssertUnwindSafe(|| deadlines.remove(id(0, 0)))).is_err());
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
        let epoch = Instant::now();
        let mut deadlines = Deadlines::new(epoch);
        let deadline = epoch + Duration::from_millis(100);
        let count = 3 * BUDGET + 7;
        for slot in 0..count {
            deadlines.insert(id(slot, 0), deadline);
        }
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
        assert!(fires >= far && fires < far + Duration::from_nanos(RES));
        assert!(deadlines.next_deadline().unwrap() <= fires);
        assert!(expire(&mut deadlines, far - Duration::from_secs(1)).is_empty());
        assert_eq!(expire(&mut deadlines, fires), [id(1, 0)]);
    }

    /// Compare request identities and rounded times with an ordered model,
    /// including early completion, cancellation, reuse and long idle jumps.
    #[test]
    fn test_randomized_deadlines_match_an_ordered_model() {
        const SLOTS: u32 = 128;
        for seed in 0..8 {
            let mut rng = TestRng::new(seed);
            let epoch = Instant::now();
            let mut deadlines = Deadlines::new(epoch);
            let mut generations = [0; SLOTS as usize];
            let mut live = BTreeMap::<u32, (u64, u64)>::new();
            let mut ordered = BTreeSet::<(u64, u32, u64)>::new();
            let mut now = 0u64;
            for step in 0..20_000 {
                match rng.random_range(0..8) {
                    0..=2 => {
                        let slot = rng.random_range(0..SLOTS);
                        if live.contains_key(&slot) {
                            continue;
                        }
                        generations[slot as usize] += 1;
                        let generation = generations[slot as usize];
                        let offset = match rng.random_range(0..5) {
                            0 => now.saturating_sub(rng.random_range(0..=10 * RES)),
                            1 => now,
                            2 => now + rng.random_range(0..=1_000 * RES),
                            _ => {
                                now + rng.random_range(0..=30 * 365 * 24 * 3600 * 1_000_000_000u64)
                            }
                        };
                        // Independent rounding, without calling the wheel.
                        let firing = offset.div_ceil(RES) * RES;
                        deadlines
                            .insert(id(slot, generation), epoch + Duration::from_nanos(offset));
                        live.insert(slot, (generation, firing));
                        ordered.insert((firing, slot, generation));
                    }
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
                    _ => {
                        now += if rng.random_range(0..10) == 0 {
                            rng.random_range(0..=24 * 3600 * 1_000_000_000u64)
                        } else {
                            rng.random_range(0..=10_000 * RES)
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
