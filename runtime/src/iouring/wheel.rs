//! Hierarchical timing wheel keyed by stable slot indices.
//!
//! Deadlines are `u64` nanoseconds rounded up to ticks of `RESOLUTION`
//! nanoseconds, so a slot never fires before its deadline and its firing time
//! is less than one tick after it (deadlines beyond [`Wheel::MAX`] are treated
//! as it). Nine levels of 64 buckets cover 54 tick bits, which span every
//! `u64` deadline because `RESOLUTION` is at least 1024. A tick is filed on
//! the level of its highest bit that differs from the wheel's base, and a due
//! list holds ticks below the base. Every bucket is an intrusive doubly
//! linked list threaded through a dense array indexed by slot, so a slot keeps
//! its identity while it cascades and removal unlinks it in O(1). Occupancy
//! bitmaps let expiry and bounds visit only occupied buckets.
//!
//! Expiry is budgeted: one pass spends one budget unit per slot it fires and
//! one per [`REFILES_PER_UNIT`] slots it refiles. Reaching a bucket detaches
//! it in O(1) by clearing its occupancy bit. The bucket keeps its list, so
//! removals still find their slots, and passes drain it, firing due slots and
//! refiling the others onto lower levels. The base moves to the detached
//! bucket's start, so a new insertion lands in that bucket only at its own
//! tick, which is due. A detached bucket drains before any other level
//! bucket, including the lower buckets its refiles land in, so a detached
//! bucket of N later slots holds back due slots in other level buckets for
//! about N / ([`REFILES_PER_UNIT`] * budget) passes.
//!
//! [`Wheel::bound`] never walks a bucket. Each bucket keeps a lower bound of
//! its ticks, exact until a slot holding the minimum is removed. A removed
//! minimum can therefore leave the bound early, which costs early passes until
//! expiry reaches the bucket and has fired or refiled every slot in it, one
//! budget's worth per pass.
//!
//! The wheel holds no payload. Its owner keys slots by a stable index of its
//! own, such as a slab index, and keeps the state behind them. Each worker's
//! sleep timers ([`super::sleep::Timers`], 1024 ns ticks) and each
//! driver's request deadlines ([`super::deadlines::Deadlines`], 2^20 ns ticks)
//! own an instance. Each owner counts nanoseconds from an [`Instant`] of its
//! own, its creation, and converts with [`InstantExt`]: an instant before
//! that epoch counts as zero, so a deadline there is due at once, and a
//! firing time converts back to an instant at or after its deadline.

use std::time::{Duration, Instant};

/// Budget units per expiry pass, by every owner: one per slot fired, one per
/// [`REFILES_PER_UNIT`] slots refiled. It bounds the expiry work between two
/// task polls, so a storm of simultaneous deadlines delays other tasks by
/// about one budget of wakes or cancellations, and a backlog drains one
/// budget per pass.
pub const BUDGET: u32 = 256;

/// Refiles that cost one unit of an expiry budget. A refile only moves a slot
/// between two lists, while a fire also starts a wake or a cancellation, so
/// a budget's refiles take about as long as its fires. Spreads of deadlines
/// registered long before them cascade in large buckets, whose refiles would
/// otherwise hold back the due slots behind them for many passes.
pub const REFILES_PER_UNIT: u32 = 16;

/// Number of wheel levels.
const LEVELS: usize = 9;

/// Bits of the tick consumed per level.
const SLOT_BITS: usize = 6;

/// Buckets per level.
const SLOTS: usize = 1 << SLOT_BITS;

/// Buckets across all levels.
const WHEEL_BUCKETS: usize = LEVELS * SLOTS;

/// Bucket of ticks below the base, which are already due.
const DUE: usize = WHEEL_BUCKETS;

/// Total bucket count.
const BUCKETS: usize = WHEEL_BUCKETS + 1;

/// Null link.
const NIL: u32 = u32::MAX;

/// Bucket tag of a slot that is not resident, and the absent pending bucket.
const NONE: u16 = u16::MAX;

/// List membership of one slot.
#[derive(Clone, Copy)]
struct Link {
    /// Rounded deadline in ticks.
    tick: u64,
    /// Previous slot in the bucket.
    prev: u32,
    /// Next slot in the bucket.
    next: u32,
    /// Bucket holding the slot, or [`NONE`].
    bucket: u16,
}

/// Link of a slot that is not resident.
const ABSENT: Link = Link {
    tick: 0,
    prev: NIL,
    next: NIL,
    bucket: NONE,
};

/// One bucket's list and a lower bound of its ticks.
#[derive(Clone, Copy)]
struct Bucket {
    /// Lower bound of the bucket's ticks, exact until a slot holding the
    /// minimum is removed.
    min: u64,
    /// First slot.
    head: u32,
    /// Last slot.
    tail: u32,
}

/// An empty bucket.
const EMPTY: Bucket = Bucket {
    min: u64::MAX,
    head: NIL,
    tail: NIL,
};

/// Conversions between instants and a wheel's nanoseconds since an epoch.
pub trait InstantExt {
    /// Nanoseconds from `epoch` to this instant: zero for an instant before
    /// `epoch`, and `u64::MAX` for one more than about 584 years after it.
    fn nanos_since(self, epoch: Instant) -> u64;

    /// The instant `nanos` after this one, or `None` for `u64::MAX`, the
    /// bound of an empty wheel, and past the end of [`Instant`]'s range.
    fn after_nanos(self, nanos: u64) -> Option<Instant>;
}

impl InstantExt for Instant {
    #[inline]
    fn nanos_since(self, epoch: Instant) -> u64 {
        let since = self.saturating_duration_since(epoch);
        u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
    }

    #[inline]
    fn after_nanos(self, nanos: u64) -> Option<Instant> {
        // The bound of an empty wheel is no time at all.
        if nanos == u64::MAX {
            return None;
        }
        self.checked_add(Duration::from_nanos(nanos))
    }
}

/// Hierarchical timing wheel with ticks of `RESOLUTION` nanoseconds.
///
/// [`Self::expire`] may receive a time older than an earlier call's, such as
/// a peer's stale sample. Expiry never moves the base past a time some caller
/// passed and treats an older time as the base, so no slot fires before its
/// firing time has passed.
pub struct Wheel<const RESOLUTION: u64> {
    /// Membership of every slot, indexed by slot.
    links: Vec<Link>,
    /// Resident slots, including a detached bucket's.
    len: usize,
    /// Reference tick for placement, never later than a time passed to
    /// [`Self::expire`] or [`Self::new`]. Every slot in a level bucket has a
    /// tick of at least `base`, and every due slot's is below it.
    base: u64,
    /// Occupied bucket bitmap per level.
    occupied: [u64; LEVELS],
    /// Bit `l` is set while level `l` has an occupied bucket.
    levels: u16,
    /// Bucket detached by expiry and not yet drained, or [`NONE`].
    pending: u16,
    /// Every bucket, the due list last.
    buckets: Box<[Bucket]>,
}

impl<const RESOLUTION: u64> Wheel<RESOLUTION> {
    /// Rejects resolutions whose 54 tick bits would not span every deadline.
    const SPANS_U64: () = assert!(
        RESOLUTION >= 1024,
        "wheel resolution must be at least 1024 ns"
    );

    /// Latest deadline with a representable firing time. Later deadlines are
    /// treated as this one.
    pub const MAX: u64 = u64::MAX / RESOLUTION * RESOLUTION;

    /// An empty wheel whose base is the tick of `now`. `now` must not be later
    /// than the current time, since ticks below the base are due at once, and
    /// should be recent, so near deadlines land on low levels.
    pub fn new(now: u64) -> Self {
        // Evaluating the assertion rejects a too fine resolution at compile
        // time, for every instantiation.
        let () = Self::SPANS_U64;
        Self {
            links: Vec::new(),
            len: 0,
            base: now / RESOLUTION,
            occupied: [0; LEVELS],
            levels: 0,
            pending: NONE,
            buckets: vec![EMPTY; BUCKETS].into_boxed_slice(),
        }
    }

    /// Whether no slot is resident.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `slot` is resident.
    pub fn contains(&self, slot: u32) -> bool {
        // A slot beyond the link array was never inserted.
        self.links
            .get(slot as usize)
            .is_some_and(|link| link.bucket != NONE)
    }

    /// Tick of `deadline`, rounded up, below `2^54`.
    #[inline]
    const fn tick_of(deadline: u64) -> u64 {
        // Clamping before rounding keeps every firing time, a tick times the
        // resolution, within `u64`.
        let deadline = if deadline > Self::MAX {
            Self::MAX
        } else {
            deadline
        };
        deadline.div_ceil(RESOLUTION)
    }

    /// The time at which a slot inserted at `deadline` fires, at most
    /// [`Self::MAX`].
    #[inline]
    pub const fn rounded(deadline: u64) -> u64 {
        Self::tick_of(deadline) * RESOLUTION
    }

    /// Bucket for a tick that is at least `base`. Both are below `2^54`, so
    /// their highest differing bit is on one of the levels.
    #[inline]
    fn bucket_for(tick: u64, base: u64) -> usize {
        assert!(tick >= base);

        // The level is the group of `SLOT_BITS` bits holding the highest bit
        // in which the tick differs from the base. Setting every bit of the
        // lowest group keeps the difference nonzero, so a tick equal to the
        // base lands on level zero.
        let diff = (tick ^ base) | (SLOTS as u64 - 1);
        let level = (63 - diff.leading_zeros() as usize) / SLOT_BITS;
        assert!(level < LEVELS);

        // Above that group the tick matches the base, so within the level the
        // tick's own bits in the group pick the bucket. They exceed the base's
        // on every level but zero, so the bucket starts after the base.
        level * SLOTS + ((tick >> (level * SLOT_BITS)) as usize & (SLOTS - 1))
    }

    /// Mark the level bucket `bucket` occupied in the bitmaps.
    const fn set_occupied(&mut self, bucket: usize) {
        if bucket < WHEEL_BUCKETS {
            let level = bucket / SLOTS;
            self.occupied[level] |= 1 << (bucket % SLOTS);
            self.levels |= 1 << level;
        }
    }

    /// Mark the level bucket `bucket` unoccupied in the bitmaps.
    const fn clear_occupied(&mut self, bucket: usize) {
        if bucket < WHEEL_BUCKETS {
            let level = bucket / SLOTS;
            self.occupied[level] &= !(1 << (bucket % SLOTS));
            if self.occupied[level] == 0 {
                self.levels &= !(1 << level);
            }
        }
    }

    /// Append `slot`, whose tick is set, to `bucket`.
    fn link(&mut self, slot: u32, bucket: usize) {
        let tick = self.links[slot as usize].tick;

        // Append at the tail, so a bucket drains in insertion order. The
        // minimum only falls here, and removals leave it alone, so it stays
        // a lower bound of the bucket's ticks without a walk.
        let entry = &mut self.buckets[bucket];
        let tail = entry.tail;
        if tail == NIL {
            entry.head = slot;
            entry.min = tick;
        } else {
            entry.min = entry.min.min(tick);
            self.links[tail as usize].next = slot;
        }
        self.buckets[bucket].tail = slot;

        let link = &mut self.links[slot as usize];
        link.prev = tail;
        link.next = NIL;
        link.bucket = bucket as u16;

        // Only a level bucket's first slot marks it occupied. A nonempty level
        // bucket is marked already, or is the detached one, which expiry
        // reaches through `pending` and which stays out of the bitmaps until
        // it drains. The due list never enters the bitmaps.
        if tail == NIL {
            self.set_occupied(bucket);
        }
    }

    /// Unlink the resident `slot` from its bucket in O(1).
    fn unlink(&mut self, slot: u32) {
        let Link {
            prev, next, bucket, ..
        } = self.links[slot as usize];
        let bucket = bucket as usize;

        // Join the neighbors, or move the bucket's head or tail past the slot
        // where it has none on that side.
        if prev != NIL {
            self.links[prev as usize].next = next;
        }
        if next != NIL {
            self.links[next as usize].prev = prev;
        }
        let entry = &mut self.buckets[bucket];
        if prev == NIL {
            entry.head = next;
        }
        if next == NIL {
            entry.tail = prev;
        }

        // An emptied bucket leaves the bitmaps, and an emptied detached
        // bucket is drained.
        if entry.head == NIL {
            *entry = EMPTY;
            self.clear_occupied(bucket);
            if bucket == self.pending as usize {
                self.pending = NONE;
            }
        }
    }

    /// Unlink `slot` and make it non-resident.
    fn detach(&mut self, slot: u32) {
        self.unlink(slot);
        self.links[slot as usize].bucket = NONE;
        self.len -= 1;
    }

    /// Lowest occupied level bucket in time order and the first tick it can hold.
    fn next_event(&self) -> Option<(usize, u64)> {
        if self.levels == 0 {
            return None;
        }

        // Every tick on a level is later than every tick on the levels below,
        // and within a level the buckets after the base's position run in
        // time order, so the earliest residents sit in the lowest occupied
        // bucket of the lowest occupied level.
        let level = self.levels.trailing_zeros() as usize;
        let slot = self.occupied[level].trailing_zeros() as usize;

        // The bucket's ticks share the base's bits above this level, so its
        // first tick is the base with this level's group set to the bucket's
        // position and every lower bit cleared.
        let block = self.base & !((1u64 << ((level + 1) * SLOT_BITS)) - 1);
        let start = block | ((slot as u64) << (level * SLOT_BITS));
        assert!(start >= self.base);
        Some((level * SLOTS + slot, start))
    }

    /// Insert `slot`, which must not be resident, at `deadline`.
    pub fn insert(&mut self, slot: u32, deadline: u64) {
        // The owner picks the slot indices, so the links grow to the highest
        // one inserted and keep that storage until [`Self::clear`].
        let index = slot as usize;
        if index >= self.links.len() {
            self.links.resize(index + 1, ABSENT);
        }
        assert_eq!(self.links[index].bucket, NONE, "slot already resident");

        // A tick below the base is already due.
        let tick = Self::tick_of(deadline);
        self.links[index].tick = tick;
        let bucket = if tick < self.base {
            DUE
        } else {
            Self::bucket_for(tick, self.base)
        };
        self.link(slot, bucket);
        self.len += 1;
    }

    /// Remove the resident `slot`, asserting its residency.
    pub fn remove(&mut self, slot: u32) {
        assert_ne!(self.links[slot as usize].bucket, NONE, "slot not resident");
        self.detach(slot);
    }

    /// Pass to `fire` the slots whose firing time is at most `now`, spending
    /// one unit of `budget` per slot fired and one per [`REFILES_PER_UNIT`]
    /// slots refiled. Due slots go first, then the detached bucket, then
    /// buckets in time order. A pass that runs out of budget leaves the rest
    /// for the next one, and [`Self::bound`] then stays at or below `now`,
    /// or at or below the base's time when `now` is older than it, while any
    /// reached slot is due, and possibly while only reached slots to refile
    /// remain (see [`Self::bound`]).
    pub fn expire(&mut self, now: u64, budget: &mut u32, fire: &mut impl FnMut(u32)) {
        // An older time is treated as the base, which never exceeds a time an
        // earlier caller passed.
        let target = (now / RESOLUTION).max(self.base);

        // Slots inserted below the base fire first.
        while *budget > 0 {
            let slot = self.buckets[DUE].head;
            if slot == NIL {
                break;
            }
            self.detach(slot);
            fire(slot);
            *budget -= 1;
        }

        // Drain the detached bucket, then detach the next bucket in time
        // order, until the budget runs out or no bucket starts by the target.
        // Partial refile units carry across buckets but not across passes.
        let mut refiles = 0;
        loop {
            while self.pending != NONE {
                if *budget == 0 {
                    return;
                }

                // Every slot taken from the head leaves the bucket, fired or
                // refiled elsewhere, so the drain always progresses.
                let slot = self.buckets[self.pending as usize].head;
                let tick = self.links[slot as usize].tick;
                if tick <= target {
                    self.detach(slot);
                    fire(slot);
                    *budget -= 1;
                } else {
                    // The detached bucket's ticks are at least the base, which
                    // is its start, so a refile lands on a lower level.
                    self.unlink(slot);
                    self.link(slot, Self::bucket_for(tick, self.base));
                    refiles += 1;
                    if refiles == REFILES_PER_UNIT {
                        refiles = 0;
                        *budget -= 1;
                    }
                }
            }

            // An exhausted budget leaves the remaining due slots, in the due
            // list or in later buckets, to the next pass.
            if *budget == 0 {
                return;
            }
            let Some((bucket, start)) = self.next_event() else {
                break;
            };
            if start > target {
                break;
            }

            // No resident is earlier than start, so the base can move there
            // and every other resident stays correctly filed. Clearing the
            // bucket's bit detaches it in O(1): it keeps its list, so removals
            // still find its slots, and the next iteration drains it.
            self.base = start;
            self.clear_occupied(bucket);
            self.pending = bucket as u16;
        }

        // Every bucket up to target was reached, so every resident is later
        // than target and stays correctly filed relative to it.
        if target > self.base {
            self.base = target;
        }
    }

    /// A time never later than the earliest resident's firing time, `u64::MAX`
    /// when empty. It is exact unless the slots holding a bucket's minimum
    /// were removed, and it never walks a bucket. A detached bucket keeps the
    /// minimum it had when expiry reached it while slots leave it, fired,
    /// removed or refiled, so after a pass that runs out of budget in that
    /// bucket, the bound can stay at or below the pass's time while only
    /// later slots to refile remain, for the few passes until it is drained.
    /// A bound at or below the time of the latest pass therefore does not
    /// strictly mean that a slot is due.
    pub fn bound(&self) -> u64 {
        // The due list, the detached bucket, and the earliest level bucket
        // together hold the earliest resident, whichever it is.
        let mut tick = u64::MAX;
        if self.buckets[DUE].head != NIL {
            tick = tick.min(self.buckets[DUE].min);
        }
        if self.pending != NONE {
            tick = tick.min(self.buckets[self.pending as usize].min);
        }
        if let Some((bucket, start)) = self.next_event() {
            // Every slot of a level zero bucket holds its start tick.
            tick = tick.min(if bucket < SLOTS {
                start
            } else {
                self.buckets[bucket].min
            });
        }
        if tick == u64::MAX {
            return u64::MAX;
        }

        // Ticks stay below 2^54, and their firing times at most MAX.
        tick * RESOLUTION
    }

    /// Remove every slot and free the storage of their links, which a later
    /// insertion allocates again.
    pub fn clear(&mut self) {
        // Replacing the vector, unlike clearing it, frees its storage.
        self.links = Vec::new();
        self.buckets.fill(EMPTY);
        self.occupied = [0; LEVELS];
        self.levels = 0;
        self.pending = NONE;
        self.len = 0;
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use commonware_utils::TestRng;
    use rand::RngExt as _;
    use std::collections::{BTreeMap, BTreeSet};

    impl<const RESOLUTION: u64> Wheel<RESOLUTION> {
        /// Number of resident slots.
        pub(crate) const fn len(&self) -> usize {
            self.len
        }

        /// Number of slots whose links the wheel has storage for.
        pub(crate) const fn capacity(&self) -> usize {
            self.links.capacity()
        }
    }

    /// Resolution of the sleep timers.
    const FINE: u64 = 1024;

    /// A coarse resolution, 2^20 ns.
    const COARSE: u64 = 1 << 20;

    /// A log-uniform value below `2^max_bits`.
    fn scaled(rng: &mut TestRng, max_bits: u32) -> u64 {
        let bits = rng.random_range(0..=max_bits);
        if bits == 0 {
            0
        } else {
            rng.random::<u64>() >> (64 - bits)
        }
    }

    #[test]
    fn test_instant_conversions_round_trip_and_saturate() {
        // Instants from the epoch on round trip exactly.
        let epoch = Instant::now();
        for nanos in [0, 1, FINE - 1, 1_000_000_007, 3_600_000_000_000] {
            let at = epoch.after_nanos(nanos).unwrap();
            assert_eq!(at.nanos_since(epoch), nanos);
        }

        // Earlier instants count as the epoch, much later ones saturate, and
        // an empty wheel's bound has no instant.
        if let Some(earlier) = epoch.checked_sub(Duration::from_secs(1)) {
            assert_eq!(earlier.nanos_since(epoch), 0);
        }
        if let Some(far) = epoch.checked_add(Duration::from_secs(600 * 365 * 24 * 60 * 60)) {
            assert_eq!(far.nanos_since(epoch), u64::MAX);
        }
        assert_eq!(epoch.after_nanos(u64::MAX), None);

        // A deadline's firing time converts back to an instant after it.
        let deadline = epoch + Duration::from_nanos(FINE + 1);
        let firing = Wheel::<FINE>::rounded(deadline.nanos_since(epoch));
        let fires = epoch + Duration::from_nanos(2 * FINE);
        assert_eq!(epoch.after_nanos(firing), Some(fires));
    }

    /// Random insertions (past, current and future, up to the end of time),
    /// removals with slot reuse, and expiries with random budgets and
    /// occasionally stale times, checked against a `BTreeMap` of firing
    /// times after every step: a fired slot was resident and its firing
    /// time had passed at the latest time any caller passed, an unbudgeted
    /// pass leaves nothing due, firing times are less than one tick after
    /// their deadlines, and the bound never exceeds the earliest firing time.
    fn model<const RESOLUTION: u64>(seed: u64, steps: usize, max_bits: u32) {
        // A wheel and its model: live slots with their firing times, the
        // same ordered by firing time, and free slots for reuse.
        let mut rng = TestRng::new(seed);
        let start = scaled(&mut rng, 50);
        let mut wheel = Wheel::<RESOLUTION>::new(start);
        let mut latest = start;
        let mut live: BTreeMap<u32, u64> = BTreeMap::new();
        let mut order: BTreeSet<(u64, u32)> = BTreeSet::new();
        let mut free: Vec<u32> = Vec::new();
        let mut slots = 0u32;
        let mut fired = Vec::new();
        for step in 0..steps {
            match rng.random_range(0..12) {
                // Insert a past, current, future, or end of time deadline,
                // whose firing time is less than one tick after it.
                0..=4 => {
                    let deadline = match rng.random_range(0..10) {
                        0 => latest.saturating_sub(scaled(&mut rng, 20)),
                        1 => latest,
                        2 => u64::MAX - scaled(&mut rng, 12),
                        _ => latest.saturating_add(scaled(&mut rng, max_bits)),
                    };
                    let slot = free.pop().unwrap_or_else(|| {
                        slots += 1;
                        slots - 1
                    });
                    wheel.insert(slot, deadline);
                    let firing = Wheel::<RESOLUTION>::rounded(deadline);
                    assert!(firing >= deadline.min(Wheel::<RESOLUTION>::MAX));
                    assert!(firing - deadline.min(Wheel::<RESOLUTION>::MAX) < RESOLUTION);
                    assert!(live.insert(slot, firing).is_none());
                    order.insert((firing, slot));
                }
                // Remove a random live slot.
                5..=7 => {
                    if live.is_empty() {
                        continue;
                    }
                    let pick = rng.random_range(0..live.len());
                    let (&slot, &firing) = live.iter().nth(pick).unwrap();
                    live.remove(&slot);
                    order.remove(&(firing, slot));
                    wheel.remove(slot);
                    free.push(slot);
                }
                // Expire at a stale time from a peer, or an advancing one,
                // with a small or unlimited budget.
                _ => {
                    let now = if rng.random_range(0..5) == 0 {
                        latest.saturating_sub(scaled(&mut rng, max_bits))
                    } else {
                        let advance = match rng.random_range(0..6) {
                            0 => 0,
                            1 => 1,
                            _ => scaled(&mut rng, max_bits),
                        };
                        latest = latest.saturating_add(advance);
                        latest
                    };
                    let limited = rng.random_range(0..3) == 0;
                    let mut budget = if limited {
                        rng.random_range(1..=8)
                    } else {
                        u32::MAX
                    };

                    // Every fired slot was live and due by the latest time.
                    fired.clear();
                    wheel.expire(now, &mut budget, &mut |slot| fired.push(slot));
                    for slot in &fired {
                        let firing = live.remove(slot).expect("stale or duplicate firing");
                        assert!(firing <= latest, "early firing at step {step}");
                        order.remove(&(firing, *slot));
                        free.push(*slot);
                    }

                    // An unbudgeted pass at the latest time leaves nothing due.
                    if !limited && now == latest {
                        assert!(
                            order.first().is_none_or(|(firing, _)| *firing > now),
                            "due slot survived at step {step}"
                        );
                    }
                }
            }

            // After every step, the wheel holds the live slots and its bound
            // is never after the earliest firing time.
            assert_eq!(wheel.len(), live.len());
            let bound = wheel.bound();
            match order.first() {
                None => assert_eq!(bound, u64::MAX, "bound of an empty wheel at {step}"),
                Some((firing, _)) => assert!(bound <= *firing, "late bound at {step}"),
            }
        }

        // Expiring at the bound always fires or raises it.
        let mut passes = 0;
        while wheel.bound() != u64::MAX {
            let bound = wheel.bound();
            let before = wheel.len();
            let mut budget = u32::MAX;
            wheel.expire(bound.max(latest), &mut budget, &mut |_| {});
            latest = latest.max(bound);
            assert!(
                wheel.len() < before || wheel.bound() > bound,
                "no progress at {bound}"
            );
            passes += 1;
            assert!(passes <= 20 * (before + 1), "too many passes");
        }
        assert_eq!(wheel.len(), 0);
    }

    #[test]
    fn test_model_fine() {
        for seed in 0..6 {
            for max_bits in [14, 30, 45, 63] {
                model::<FINE>(seed, 20_000, max_bits);
            }
        }
    }

    #[test]
    fn test_model_coarse() {
        for seed in 0..6 {
            for max_bits in [24, 40, 63] {
                model::<COARSE>(seed, 20_000, max_bits);
            }
        }
    }

    #[test]
    fn test_rounding_is_never_early() {
        // A deadline inside a tick rounds up to the end of that tick.
        let mut wheel = Wheel::<FINE>::new(0);
        wheel.insert(0, 2_500);
        assert_eq!(Wheel::<FINE>::rounded(2_500), 3_072);
        assert_eq!(wheel.bound(), 3_072);

        // It fires at the rounded time, not one nanosecond earlier.
        let mut fired = Vec::new();
        let mut budget = u32::MAX;
        wheel.expire(3_071, &mut budget, &mut |slot| fired.push(slot));
        assert!(fired.is_empty());
        wheel.expire(3_072, &mut budget, &mut |slot| fired.push(slot));
        assert_eq!(fired, [0]);
    }

    #[test]
    fn test_boundaries_and_the_end_of_time() {
        // Deadlines on and around tick and level boundaries, up to the end of
        // time and past it.
        let thirty_years = 30u64 * 365 * 24 * 3600 * 1_000_000_000;
        let deadlines = [
            0,
            1,
            1023,
            1024,
            1025,
            65_535,
            65_536,
            65_537,
            4_194_305,
            thirty_years - 1,
            thirty_years,
            i64::MAX as u64,
            Wheel::<FINE>::MAX,
            u64::MAX,
        ];
        let mut wheel = Wheel::<FINE>::new(0);
        for (slot, deadline) in deadlines.iter().enumerate() {
            wheel.insert(slot as u32, *deadline);
        }

        // Expire at increasing times, never firing a slot before its rounded
        // deadline.
        let mut seen = 0;
        for now in [
            0,
            1023,
            1024,
            65_536,
            4_195_328,
            thirty_years - 1,
            thirty_years + 1024,
            i64::MAX as u64,
            u64::MAX,
        ] {
            let mut budget = u32::MAX;
            wheel.expire(now, &mut budget, &mut |slot| {
                assert!(Wheel::<FINE>::rounded(deadlines[slot as usize]) <= now);
                seen += 1;
            });
        }

        // Every slot fired, including those clamped to the end of time.
        assert_eq!(seen, deadlines.len());
        assert_eq!(wheel.bound(), u64::MAX);
    }

    #[test]
    fn test_budget_leaves_a_backlog_that_drains() {
        let mut wheel = Wheel::<FINE>::new(0);

        // A storm far enough ahead to sit on a high level, with deadlines
        // jittered by tens of nanoseconds.
        let deadline = 50_000_000;
        for slot in 0..1000u32 {
            wheel.insert(slot, deadline + u64::from(slot % 7) * 13);
        }

        // Two ticks early, nothing fires.
        let mut fired = Vec::new();
        let mut budget = 256;
        wheel.expire(deadline - 2048, &mut budget, &mut |slot| fired.push(slot));
        assert!(fired.is_empty());

        // At one fixed time, each pass fires at most one budget.
        let now = Wheel::<FINE>::rounded(deadline + 100);
        let mut passes = 0;
        while !wheel.is_empty() {
            let mut budget = 256;
            let before = fired.len();
            wheel.expire(now, &mut budget, &mut |slot| fired.push(slot));
            passes += 1;

            // Due slots of a detached bucket fire rather than refile.
            assert!(fired.len() > before, "pass {passes} fired nothing");
            assert!(fired.len() - before <= 256);
            if !wheel.is_empty() {
                assert!(wheel.bound() <= now, "backlog left with a late bound");
            }
        }

        // The storm drained completely within a few passes.
        assert_eq!(fired.len(), 1000);
        assert!((4..=6).contains(&passes), "{passes} passes");
    }

    #[test]
    fn test_refiles_cost_a_fraction_of_the_budget() {
        // One high bucket lists a budget's worth of later slots ahead of the
        // one due first, so expiry refiles them all before it reaches it.
        let mut wheel = Wheel::<FINE>::new(0);
        let deadline = 50_000_000;
        let later = REFILES_PER_UNIT * (BUDGET - 1);
        for slot in 0..later {
            wheel.insert(slot, deadline + FINE + u64::from(slot) * 64);
        }
        wheel.insert(later, deadline);

        // Once it is due, one pass refiles the later slots and still fires it.
        let now = Wheel::<FINE>::rounded(deadline);
        let mut fired = Vec::new();
        let mut budget = BUDGET;
        wheel.expire(now, &mut budget, &mut |slot| fired.push(slot));
        assert_eq!(fired, [later]);
        assert_eq!(budget, 0);

        // The refiled slots fire at their own times.
        let end = Wheel::<FINE>::rounded(deadline + FINE + u64::from(later) * 64);
        while !wheel.is_empty() {
            let mut budget = BUDGET;
            wheel.expire(end, &mut budget, &mut |slot| fired.push(slot));
        }
        assert_eq!(fired.len(), later as usize + 1);
    }

    #[test]
    fn test_removed_minimum_leaves_a_lower_bound_without_walks() {
        // One high bucket whose minimum is removed repeatedly. The bound stays
        // early instead of walking the bucket.
        let mut wheel = Wheel::<FINE>::new(0);
        let base = 1u64 << 40;
        for slot in 0..10_000u32 {
            wheel.insert(slot, base + u64::from(slot) * 2048);
        }
        assert_eq!(wheel.bound(), Wheel::<FINE>::rounded(base));
        for slot in 0..9_999u32 {
            wheel.remove(slot);
            assert!(wheel.bound() <= Wheel::<FINE>::rounded(base + u64::from(slot + 1) * 2048));
        }

        // One early pass reaches the bucket and refiles it, after which the
        // bound is exact.
        let mut budget = u32::MAX;
        let mut fired = Vec::new();
        wheel.expire(wheel.bound(), &mut budget, &mut |slot| fired.push(slot));
        assert!(fired.is_empty());
        assert_eq!(
            wheel.bound(),
            Wheel::<FINE>::rounded(base + 9_999 * 2048),
            "a refiled bucket reports its exact minimum"
        );
    }

    #[test]
    fn test_insertion_into_a_detached_due_bucket_fires() {
        // Four slots share one deadline.
        let mut wheel = Wheel::<FINE>::new(0);
        let deadline = 100 * FINE;
        for slot in 0..4u32 {
            wheel.insert(slot, deadline);
        }

        // Cascade the slots to level zero, one tick before they are due.
        let mut budget = u32::MAX;
        let mut fired = Vec::new();
        wheel.expire(deadline - FINE, &mut budget, &mut |slot| fired.push(slot));
        assert!(fired.is_empty());
        let mut budget = 2;
        wheel.expire(deadline, &mut budget, &mut |slot| fired.push(slot));
        assert_eq!(fired.len(), 2);

        // The base is the detached level zero bucket's tick, so this joins it.
        wheel.insert(9, deadline);
        assert_eq!(wheel.links[9].bucket, wheel.pending);
        assert_eq!(wheel.bound(), deadline);
        let mut budget = u32::MAX;
        wheel.expire(deadline, &mut budget, &mut |slot| fired.push(slot));
        assert_eq!(fired.len(), 5);
        assert_eq!(wheel.bound(), u64::MAX);
    }

    #[test]
    fn test_clear_empties_and_allows_reuse() {
        // A budgeted pass leaves a partly drained backlog for clear to discard.
        let mut wheel = Wheel::<FINE>::new(0);
        for slot in 0..10u32 {
            wheel.insert(slot, 1_000_000 * u64::from(slot));
        }
        let mut budget = 3;
        wheel.expire(5_000_000, &mut budget, &mut |_| {});

        // Clearing leaves an empty wheel that holds no link storage.
        wheel.clear();
        assert_eq!(wheel.len(), 0);
        assert_eq!(wheel.bound(), u64::MAX);
        assert_eq!(wheel.capacity(), 0);

        // A cleared wheel accepts a slot again and fires it.
        wheel.insert(3, 7);
        assert_eq!(wheel.len(), 1);
        let mut budget = u32::MAX;
        let mut fired = Vec::new();
        wheel.expire(u64::MAX, &mut budget, &mut |slot| fired.push(slot));
        assert_eq!(fired, [3]);
    }
}
