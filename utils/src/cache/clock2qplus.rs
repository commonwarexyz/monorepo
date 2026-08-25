//! The Clock2Q+ cache replacement policy.
//!
//! Clock2Q+ separates resident entries into two partitions:
//!
//! - Small is a first-in, first-out probation queue where new entries wait for
//!   evidence of reuse.
//! - Main is a CLOCK ring that protects the established working set. A sweep
//!   gives referenced entries a second chance and evicts the first unreferenced
//!   entry.
//!
//! The policy also keeps a bounded Ghost queue containing only the keys of
//! entries recently evicted from Small. Ghost does not hold values or consume
//! resident cache capacity. Finding a requested key in Ghost demonstrates reuse
//! after eviction, so the key bypasses Small and enters Main. Keys seen only
//! once pass through Small and leave bounded history in Ghost without
//! displacing the established Main working set.
//!
//! # Admission and Eviction
//!
//! New entries normally enter the head of Small. When an entry reaches the
//! Small tail, an unreferenced entry is evicted and its key is recorded in
//! Ghost, while a referenced entry is promoted to Main. A Ghost hit enters Main
//! directly and consumes the matching history entry.
//!
//! # Correlation Filtering
//!
//! Up to the newest half of Small forms a correlation window. Hits in that
//! window are ignored, which prevents a burst of closely spaced accesses from
//! making a cold entry appear hot. Once enough newer entries arrive, the entry
//! leaves the window permanently. A later hit sets its reference bit and
//! promotes it when it reaches the Small tail.
//!
//! # Sizing and State
//!
//! This implementation targets the paper's fixed proportions. For integer
//! capacity `C`, Small is `max(C / 10, 1)` when `C > 1`, Main gets the
//! remainder, and Ghost is `C / 2`. The correlation window is half of Small,
//! rounded up. A capacity of one uses Main only. Resident keys and values
//! remain in stable [super::Cache] slots. Resident topology and Ghost history are
//! policy-owned, while each slot's correlation marker and reference bit are
//! stored inline as [Policy::SlotState].
//!
//! # References
//!
//! - [Clock2Q+: A Simple and Efficient Replacement Algorithm for Metadata
//!   Cache in VMware vSAN](https://arxiv.org/abs/2511.21958)

use super::{Cache, Claimed, Hasher, Policy, Slot};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{
    hash::Hash,
    num::NonZeroUsize,
    ops::Index,
    sync::atomic::{AtomicU8, Ordering},
};
use hashbrown::HashMap;

/// Sentinel used when a policy-owned slot has no neighbor.
const UNLINKED: usize = usize::MAX;
/// Slot-state bit set after an eligible resident hit.
const REFERENCED: u8 = 1 << 0;
/// Slot-state bit set while a Small resident is in the correlation window.
const CORRELATED: u8 = 1 << 1;

/// Converts the internal link sentinel into an optional slot.
#[inline]
const fn linked(slot: usize) -> Option<usize> {
    if slot == UNLINKED { None } else { Some(slot) }
}

/// Where a resident slot participates in the replacement policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Location {
    /// The cache slot is not attached to either resident partition.
    Free,
    /// An entry in the Small queue.
    Small,
    /// An entry in the Main CLOCK ring.
    Main,
}

/// Policy-owned topology for a stable cache slot.
#[derive(Clone, Copy)]
struct ResidentSlot {
    /// Partition containing the resident, or [`Location::Free`] when detached.
    location: Location,
    /// Previous entry toward the head of Small, or in Main's circular ring.
    prev: usize,
    /// Next entry toward the tail of Small, or in Main's circular ring.
    next: usize,
    /// Small admission generation, used only while this entry is correlated.
    admitted_at: usize,
}

impl Default for ResidentSlot {
    fn default() -> Self {
        Self {
            location: Location::Free,
            prev: UNLINKED,
            next: UNLINKED,
            admitted_at: 0,
        }
    }
}

/// Resident partition selected for an incoming key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Admission {
    /// Admit at the head of the Small queue.
    Small,
    /// Admit immediately before the hand in the Main CLOCK ring.
    Main,
}

/// Storage action selected for one confirmed-miss insertion.
#[derive(Clone, Copy)]
enum InsertionPlan {
    /// Claim unused cache capacity.
    Vacant,
    /// Replace one resident.
    Evict {
        /// Resident selected for eviction.
        victim: Slot,
    },
    /// Promote a Small resident and replace a separate Main resident.
    PromoteThenEvict {
        /// Small tail retained and moved to Main.
        promoted: Slot,
        /// Main resident selected for eviction.
        victim: Slot,
    },
}

impl InsertionPlan {
    /// Returns the resident selected for replacement, if any.
    const fn victim(self) -> Option<Slot> {
        match self {
            Self::Vacant => None,
            Self::Evict { victim } | Self::PromoteThenEvict { victim, .. } => Some(victim),
        }
    }
}

/// Policy state stored inline with each Clock2Q+ cache slot.
///
/// The correlation marker and reference bit share one atomic byte, so a shared
/// hit needs no access to policy-owned queue topology. Relaxed ordering is
/// sufficient because these bits affect only replacement decisions and do not
/// publish resident keys or values.
#[repr(transparent)]
#[derive(Default)]
pub struct SlotState(AtomicU8);

impl SlotState {
    /// Returns the initial state for a resident entering `admission`.
    #[inline]
    const fn new(admission: Admission) -> Self {
        let state = match admission {
            Admission::Small => CORRELATED,
            Admission::Main => 0,
        };
        Self(AtomicU8::new(state))
    }

    /// Records a hit through a shared cache reference.
    ///
    /// Hits inside the correlation window are ignored. The conditional store
    /// also avoids dirtying the cache line again after the bit is already set.
    #[inline]
    fn record_hit(&self) {
        let current = self.0.load(Ordering::Relaxed);
        if current & (CORRELATED | REFERENCED) == 0 {
            self.0.store(REFERENCED, Ordering::Relaxed);
        }
    }

    /// Records a hit while the cache is already exclusively borrowed.
    #[inline]
    fn record_hit_mut(&mut self) {
        let current = self.0.get_mut();
        if *current & CORRELATED == 0 {
            *current |= REFERENCED;
        }
    }

    /// Returns whether a Small resident has earned promotion.
    #[inline]
    fn earned_promotion(&self) -> bool {
        self.0.load(Ordering::Relaxed) & (CORRELATED | REFERENCED) == REFERENCED
    }

    /// Consumes one Main reference bit.
    #[inline]
    fn take_reference(&self) -> bool {
        if self.0.load(Ordering::Relaxed) & REFERENCED == 0 {
            return false;
        }
        self.0.store(0, Ordering::Relaxed);
        true
    }

    /// Clears correlation and reference state during an exclusive transition.
    #[inline]
    fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// State and endpoints for the Small queue.
struct SmallQueue {
    /// Maximum number of Small residents.
    capacity: usize,
    /// Admission age at which a resident leaves the correlation window.
    correlation_window: usize,
    /// Newest Small resident.
    head: Option<Slot>,
    /// Oldest Small resident.
    tail: Option<Slot>,
    /// Oldest resident still inside the correlation window.
    young_tail: Option<Slot>,
    /// Monotonic count of Small admissions, including removed entries.
    admissions: usize,
    /// Current number of Small residents.
    len: usize,
}

impl SmallQueue {
    /// Constructs an empty Small queue with its derived correlation window.
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            correlation_window: capacity.div_ceil(2),
            head: None,
            tail: None,
            young_tail: None,
            admissions: 0,
            len: 0,
        }
    }

    /// Attaches a free stable slot at the queue head.
    #[inline]
    fn push<I: Index<Slot, Output = SlotState>>(
        &mut self,
        states: &I,
        slots: &mut [ResidentSlot],
        slot: Slot,
    ) {
        // Admission count, rather than live queue length, makes correlation age
        // monotonic across explicit removal and retention. Wrapping remains
        // valid because a correlated resident leaves within one bounded window,
        // long before the counter can complete a full cycle.
        self.admissions = self.admissions.wrapping_add(1);
        let old_head = self.head;
        {
            let entry = &mut slots[slot];
            assert_eq!(entry.location, Location::Free);
            entry.location = Location::Small;
            entry.prev = UNLINKED;
            entry.next = old_head.unwrap_or(UNLINKED);
            entry.admitted_at = self.admissions;
        }
        if let Some(head) = old_head {
            slots[head].prev = slot;
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
        self.len += 1;

        let demoted = *self.young_tail.get_or_insert(slot);

        // Only the oldest correlated survivor can leave the window after one
        // new admission because Small preserves admission order.
        let age = self.admissions.wrapping_sub(slots[demoted].admitted_at);
        if age < self.correlation_window {
            return;
        }

        let new_boundary = slots[demoted].prev;
        assert_ne!(new_boundary, UNLINKED);

        // Discard references made inside the correlation window. Only a hit
        // after the entry becomes old should promote it to Main.
        states[demoted].reset();
        slots[demoted].admitted_at = 0;
        self.young_tail = Some(new_boundary);
    }

    /// Detaches a resident and repairs the queue and correlation boundary.
    #[inline]
    fn unlink(&mut self, slots: &mut [ResidentSlot], slot: Slot) {
        assert_eq!(slots[slot].location, Location::Small);
        let prev = slots[slot].prev;
        let next = slots[slot].next;
        if prev != UNLINKED {
            slots[prev].next = next;
        } else {
            self.head = linked(next);
        }
        if next != UNLINKED {
            slots[next].prev = prev;
        } else {
            self.tail = linked(prev);
        }

        self.len -= 1;

        // Removing the correlation boundary shrinks the live window without
        // making any older resident young again.
        if self.young_tail == Some(slot) {
            self.young_tail = linked(prev);
        }
        slots[slot] = ResidentSlot::default();
    }

    /// Resets all Small endpoints and counters.
    const fn clear(&mut self) {
        self.head = None;
        self.tail = None;
        self.young_tail = None;
        self.admissions = 0;
        self.len = 0;
    }
}

/// Circular resident topology and replacement hand for Main.
///
/// Unlike the Small and Ghost queues, Main has no head or tail. Its entries
/// form a ring, and the CLOCK hand sweeps that ring for an unreferenced victim.
struct MainRing {
    /// Maximum number of Main residents.
    capacity: usize,
    /// Next resident considered for eviction.
    hand: Option<Slot>,
    /// Current number of Main residents.
    len: usize,
}

impl MainRing {
    /// Constructs an empty Main ring.
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            hand: None,
            len: 0,
        }
    }

    /// Sweeps the CLOCK hand to the first unreferenced resident.
    #[inline]
    fn select<I: Index<Slot, Output = SlotState>>(
        &mut self,
        states: &I,
        slots: &[ResidentSlot],
    ) -> Slot {
        loop {
            let slot = self.hand.expect("nonempty Main must have a hand");
            if states[slot].take_reference() {
                // A set bit grants one second chance. Continue from the next
                // resident after consuming it.
                self.hand = Some(slots[slot].next);
                continue;
            }
            return slot;
        }
    }

    /// Attaches a free slot immediately before the hand.
    #[inline]
    fn push(&mut self, slots: &mut [ResidentSlot], slot: Slot) {
        assert!(self.len < self.capacity);
        let Some(hand) = self.hand else {
            // A one-entry ring links the resident to itself and points the hand
            // at that sole eviction candidate.
            let entry = &mut slots[slot];
            assert_eq!(entry.location, Location::Free);
            entry.location = Location::Main;
            entry.prev = slot;
            entry.next = slot;
            self.hand = Some(slot);
            self.len = 1;
            return;
        };

        // New residents start behind the current hand, so they are considered
        // only after the existing CLOCK sweep reaches them.
        let prev = slots[hand].prev;
        assert_ne!(prev, UNLINKED);
        {
            let entry = &mut slots[slot];
            assert_eq!(entry.location, Location::Free);
            entry.location = Location::Main;
            entry.prev = prev;
            entry.next = hand;
        }
        slots[prev].next = slot;
        slots[hand].prev = slot;
        self.len += 1;
    }

    /// Detaches a resident and advances the hand when necessary.
    #[inline]
    fn unlink(&mut self, slots: &mut [ResidentSlot], slot: Slot) {
        assert_eq!(slots[slot].location, Location::Main);
        if self.len == 1 {
            assert_eq!(self.hand, Some(slot));
            self.hand = None;
            self.len = 0;
        } else {
            let prev = slots[slot].prev;
            let next = slots[slot].next;
            assert_ne!(prev, UNLINKED);
            assert_ne!(next, UNLINKED);
            slots[prev].next = next;
            slots[next].prev = prev;
            if self.hand == Some(slot) {
                self.hand = Some(next);
            }
            self.len -= 1;
        }
        slots[slot] = ResidentSlot::default();
    }

    /// Resets the Main hand and resident count.
    const fn clear(&mut self) {
        self.hand = None;
        self.len = 0;
    }
}

/// A key-only entry in the bounded Ghost queue.
struct GhostSlot<K> {
    /// Historical key, or `None` when this slot is available for reuse.
    key: Option<K>,
    /// Previous entry toward the Ghost head.
    prev: usize,
    /// Next entry toward the Ghost tail.
    next: usize,
}

/// Exact bounded history of keys recently evicted from Small.
///
/// Ghost stores keys without values, so it records recent eviction history
/// without consuming resident cache capacity. A later request for a recorded
/// key demonstrates reuse and admits the key directly to Main. The hash index
/// provides exact membership checks, while the linked queue discards the oldest
/// history when it reaches its bound.
struct GhostQueue<K> {
    /// Exact key membership mapped to queue positions.
    index: HashMap<K, usize, Hasher>,
    /// Storage for linked historical entries.
    slots: Vec<GhostSlot<K>>,
    /// Detached positions available for reuse.
    free: Vec<usize>,
    /// Newest historical entry.
    head: Option<usize>,
    /// Oldest historical entry.
    tail: Option<usize>,
    /// Maximum number of historical entries.
    capacity: usize,
}

impl<K: Hash + Eq + Clone> GhostQueue<K> {
    /// Constructs empty exact history bounded by `capacity`.
    fn new(capacity: usize) -> Self {
        Self {
            index: HashMap::with_capacity_and_hasher(capacity, Hasher::default()),
            slots: Vec::with_capacity(capacity),
            free: Vec::with_capacity(capacity),
            head: None,
            tail: None,
            capacity,
        }
    }

    /// Adds an evicted Small key at the queue head.
    #[inline]
    fn push(&mut self, key: K) {
        if self.capacity == 0 {
            return;
        }

        // Prefer recycled storage, then grow to the Ghost bound, then reuse
        // the oldest live slot after removing its previous key.
        let slot = if let Some(slot) = self.free.pop() {
            slot
        } else if self.slots.len() < self.capacity {
            let slot = self.slots.len();
            self.slots.push(GhostSlot {
                key: None,
                prev: UNLINKED,
                next: UNLINKED,
            });
            slot
        } else {
            let slot = self.tail.expect("full Ghost must have a tail");
            let historical = self.unlink(slot);
            let removed = self.index.remove(&historical);
            assert_eq!(removed, Some(slot));
            slot
        };

        let old_head = self.head;
        {
            let entry = &mut self.slots[slot];
            assert!(entry.key.is_none());

            // Ghost keeps one key in its hash index and one in its queue slot,
            // which avoids per-entry shared ownership between the structures.
            entry.key = Some(key.clone());
            entry.prev = UNLINKED;
            entry.next = old_head.unwrap_or(UNLINKED);
        }
        if let Some(head) = old_head {
            self.slots[head].prev = slot;
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
        self.index.insert(key, slot);
    }

    /// Removes exact history for `key` and reports whether it was present.
    #[inline]
    fn discard(&mut self, key: &K) -> bool {
        let Some(slot) = self.index.remove(key) else {
            return false;
        };
        let _historical = self.unlink(slot);

        // Recycle the position before dropping the key, so a panicking
        // destructor cannot strand the detached slot outside the free list.
        self.free.push(slot);
        true
    }

    /// Detaches one historical entry and returns its owned key.
    #[inline]
    fn unlink(&mut self, slot: usize) -> K {
        let prev = self.slots[slot].prev;
        let next = self.slots[slot].next;
        if prev != UNLINKED {
            self.slots[prev].next = next;
        } else {
            self.head = linked(next);
        }
        if next != UNLINKED {
            self.slots[next].prev = prev;
        } else {
            self.tail = linked(prev);
        }

        let key = self.slots[slot]
            .key
            .take()
            .expect("linked Ghost entry must have a key");
        self.slots[slot].prev = UNLINKED;
        self.slots[slot].next = UNLINKED;
        key
    }

    /// Removes all historical entries and reusable positions.
    fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.free.clear();
        self.head = None;
        self.tail = None;
    }
}

/// Clock2Q+ admission and eviction policy.
///
/// Clock2Q+ divides residents between a Small queue and a Main CLOCK ring. New
/// keys enter Small, while keys found in bounded Ghost history enter Main.
/// Hits to the newest portion of Small are ignored to filter correlated access.
/// An eligible Small hit marks the resident for promotion when it reaches the
/// queue tail.
///
/// The policy owns resident topology, partition sizes, the Main CLOCK hand, and
/// exact bounded Ghost history. Resident keys and values remain in [Cache].
/// The target proportions are 10% Small, 90% Main, and 50% Ghost, with a
/// correlation window covering half of Small. Integer sizes use floor division,
/// except that Small receives at least one slot when total capacity exceeds
/// one. A capacity of one uses Main as a one-entry CLOCK.
///
/// Resident values stay in stable cache slots while resident links remain in the
/// policy. Hits mutate only relaxed atomic slot state, so readers can share the
/// cache behind a reader-writer lock without serializing.
///
/// See [Clock2Q+: A Simple and Efficient Replacement Algorithm for Metadata
/// Cache in VMware vSAN](https://arxiv.org/abs/2511.21958).
///
/// # Example
///
/// ```
/// use commonware_utils::cache::{Cache, Clock2QPlus};
/// use core::num::NonZeroUsize;
///
/// let mut cache = Cache::<u64, u64, Clock2QPlus<u64>>::new(
///     NonZeroUsize::new(100).unwrap(),
/// );
/// cache.put(7, 49);
/// assert_eq!(cache.get(&7), Some(&49));
/// ```
pub struct Clock2QPlus<K> {
    /// Resident topology and admission age indexed by the cache's stable slots.
    ///
    /// The cache owns keys, values, and inline [`SlotState`]. This parallel
    /// array is required for policy-owned links that must also be available to
    /// [`Policy::remove`], which receives a slot identifier but no state view.
    slots: Vec<ResidentSlot>,
    /// Admission queue and correlation-window state.
    small: SmallQueue,
    /// Eviction ring and CLOCK hand.
    main: MainRing,
    /// Exact bounded history used for scan-resistant admission.
    ghost: GhostQueue<K>,
}

impl<K: Hash + Eq + Clone> Clock2QPlus<K> {
    /// Constructs empty policy metadata for `capacity` resident slots.
    fn with_capacity(capacity: NonZeroUsize) -> Self {
        let capacity = capacity.get();

        // Keep tiny caches usable while approaching the paper's target ratios
        // with integer arithmetic at normal capacities.
        let small_capacity = if capacity == 1 {
            0
        } else {
            (capacity / 10).max(1)
        };
        let main_capacity = capacity - small_capacity;
        let ghost_capacity = capacity / 2;

        Self {
            slots: vec![ResidentSlot::default(); capacity],
            small: SmallQueue::new(small_capacity),
            main: MainRing::new(main_capacity),
            ghost: GhostQueue::new(ghost_capacity),
        }
    }

    /// Chooses the resident partition for an incoming key.
    #[inline]
    const fn admission(&self, ghost_hit: bool, has_vacancy: bool) -> Admission {
        // A Ghost hit bypasses Small. During warm-up, Small fills to its target
        // before additional vacant cache slots are assigned to Main.
        if ghost_hit
            || self.small.capacity == 0
            || (has_vacancy && self.small.len >= self.small.capacity)
        {
            Admission::Main
        } else {
            Admission::Small
        }
    }

    /// Plans the resident transition for one confirmed-miss insertion.
    #[inline]
    fn plan<I: Index<Slot, Output = SlotState>>(
        &mut self,
        states: &I,
        admission: Admission,
        has_vacancy: bool,
    ) -> InsertionPlan {
        match admission {
            Admission::Small if has_vacancy => InsertionPlan::Vacant,
            Admission::Small => {
                let tail = self.small.tail.expect("full cache must have a Small tail");
                if !states[tail].earned_promotion() {
                    return InsertionPlan::Evict { victim: tail };
                }

                // A full cache and bounded partitions imply Main is also full.
                // Promote the referenced Small tail while the incoming entry
                // reuses the Main victim selected here.
                assert_eq!(self.main.len, self.main.capacity);
                let victim = self.main.select(states, &self.slots);
                InsertionPlan::PromoteThenEvict {
                    promoted: tail,
                    victim,
                }
            }
            Admission::Main if self.main.len == self.main.capacity => InsertionPlan::Evict {
                victim: self.main.select(states, &self.slots),
            },
            Admission::Main => {
                // Main can grow only while the cache has unused capacity.
                assert!(has_vacancy);
                InsertionPlan::Vacant
            }
        }
    }

    /// Attaches a free stable slot to its selected resident partition.
    #[inline]
    fn attach<I: Index<Slot, Output = SlotState>>(
        &mut self,
        states: &I,
        slot: Slot,
        admission: Admission,
    ) {
        match admission {
            Admission::Small => self.small.push(states, &mut self.slots, slot),
            Admission::Main => self.main.push(&mut self.slots, slot),
        }
    }

    /// Detaches a resident and returns its previous partition.
    #[inline]
    fn unlink_resident(&mut self, slot: Slot) -> Location {
        let location = self.slots[slot].location;
        match location {
            Location::Small => self.small.unlink(&mut self.slots, slot),
            Location::Main => self.main.unlink(&mut self.slots, slot),
            Location::Free => unreachable!("resident slot cannot be free"),
        }
        location
    }
}

impl<K: Hash + Eq + Clone> Policy<K> for Clock2QPlus<K> {
    type SlotState = SlotState;

    fn new(capacity: NonZeroUsize) -> Self {
        Self::with_capacity(capacity)
    }

    #[inline]
    fn hit(&self, _slot: Slot, state: &SlotState) {
        state.record_hit();
    }

    #[inline]
    fn hit_mut(&mut self, _slot: Slot, state: &mut SlotState) {
        state.record_hit_mut();
    }

    fn insert<I, C>(
        &mut self,
        states: &I,
        key: &K,
        has_vacancy: bool,
        claim: C,
    ) -> (Slot, SlotState)
    where
        I: Index<Slot, Output = SlotState>,
        C: FnOnce(Option<Slot>) -> Claimed<K>,
    {
        // Consult and consume exact Ghost history at insertion time. Keeping
        // this separate makes partition selection free of hidden mutation.
        let ghost_hit = self.ghost.discard(key);
        let admission = self.admission(ghost_hit, has_vacancy);
        let plan = self.plan(states, admission, has_vacancy);
        let victim = plan.victim();

        // Claim transfers an evicted key to the policy without cloning it.
        let slot = match (plan, claim(victim)) {
            (InsertionPlan::Vacant, Claimed::Vacant(slot)) => slot,
            (
                InsertionPlan::Evict { victim } | InsertionPlan::PromoteThenEvict { victim, .. },
                Claimed::Evicted(key),
            ) => {
                let location = self.unlink_resident(victim);

                // Only Small evictions become Ghost evidence. Main victims
                // have already passed the admission filter.
                if location == Location::Small {
                    self.ghost.push(key);
                }
                victim
            }
            _ => unreachable!("cache claim must match the insertion plan"),
        };

        assert_eq!(self.slots[slot].location, Location::Free);
        if let InsertionPlan::PromoteThenEvict { promoted, .. } = plan {
            // Claim has detached the Main victim from the cache index and the
            // previous arm has detached it from the ring. Move the retained
            // Small tail into the resulting Main vacancy.
            self.small.unlink(&mut self.slots, promoted);
            states[promoted].reset();
            self.main.push(&mut self.slots, promoted);
        }
        self.attach(states, slot, admission);
        (slot, SlotState::new(admission))
    }

    fn remove(&mut self, slot: Option<Slot>, key: &K) {
        if let Some(slot) = slot {
            // Resident and Ghost keys are disjoint, so resident removal can
            // detach directly without probing nonresident history.
            self.unlink_resident(slot);
        } else {
            self.ghost.discard(key);
        }
    }

    fn clear(&mut self) {
        self.slots.fill(ResidentSlot::default());
        self.small.clear();
        self.main.clear();
        self.ghost.clear();
    }
}

impl<K: Hash + Eq + Clone, V> core::fmt::Debug for Cache<K, V, Clock2QPlus<K>> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Clock2QPlus")
            .field("len", &self.index.len())
            .field("capacity", &self.policy.slots.len())
            .field("small_target", &self.policy.small.capacity)
            .field("small_len", &self.policy.small.len)
            .field("main_len", &self.policy.main.len)
            .field("ghost_len", &self.policy.ghost.index.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NZUsize, cache::Cache, sync::RwLock};
    use std::{
        collections::HashSet,
        sync::{Arc, Barrier},
        thread,
    };

    type TestCache<K, V> = Cache<K, V, Clock2QPlus<K>>;

    impl<K: Hash + Eq + Clone + core::fmt::Debug, V> Cache<K, V, Clock2QPlus<K>> {
        /// Returns the number of residents attached to either partition.
        const fn residents(&self) -> usize {
            self.policy.small.len + self.policy.main.len
        }

        /// Returns the packed policy state for a resident slot.
        fn bits(&self, slot: Slot) -> u8 {
            self.slots[slot].state.0.load(Ordering::Relaxed)
        }

        /// Returns Small slot order from newest to oldest.
        fn small_order(&self) -> Vec<usize> {
            let mut order = Vec::with_capacity(self.policy.small.len);
            let mut current = self.policy.small.head;
            while let Some(slot) = current {
                order.push(slot);
                current = linked(self.policy.slots[slot].next);
            }
            order
        }

        /// Returns Main slot order starting at the CLOCK hand.
        fn main_order(&self) -> Vec<usize> {
            let mut order = Vec::with_capacity(self.policy.main.len);
            let Some(hand) = self.policy.main.hand else {
                return order;
            };
            let mut current = hand;
            loop {
                order.push(current);
                current = self.policy.slots[current].next;
                assert_ne!(current, UNLINKED);
                if current == hand {
                    return order;
                }
            }
        }

        /// Returns Ghost slot order from newest to oldest.
        fn ghost_order(&self) -> Vec<usize> {
            let mut order = Vec::with_capacity(self.policy.ghost.index.len());
            let mut current = self.policy.ghost.head;
            while let Some(slot) = current {
                order.push(slot);
                current = linked(self.policy.ghost.slots[slot].next);
            }
            order
        }

        /// Returns Small keys from newest to oldest.
        fn small_keys(&self) -> Vec<K> {
            self.small_order()
                .into_iter()
                .map(|slot| self.slots[slot].key.clone())
                .collect()
        }

        /// Returns Main keys starting at the CLOCK hand.
        fn main_keys(&self) -> Vec<K> {
            self.main_order()
                .into_iter()
                .map(|slot| self.slots[slot].key.clone())
                .collect()
        }

        /// Returns Ghost keys from newest to oldest.
        fn ghost_keys(&self) -> Vec<K> {
            self.ghost_order()
                .into_iter()
                .map(|slot| {
                    self.policy.ghost.slots[slot]
                        .key
                        .as_ref()
                        .expect("live Ghost entry must have a key")
                        .clone()
                })
                .collect()
        }

        /// Asserts the Clock2Q+ policy's invariants hold.
        pub(crate) fn check_policy_invariants(&self) {
            let policy = &self.policy;
            assert!(self.residents() <= policy.slots.len());
            assert!(policy.small.len <= policy.small.capacity);
            assert!(policy.main.len <= policy.main.capacity);
            assert_eq!(self.index.len(), self.residents());
            assert_eq!(self.index.len() + self.free.len(), self.slots.len());

            let free: HashSet<_> = self.free.iter().copied().collect();
            assert_eq!(free.len(), self.free.len(), "duplicate resident free slot");
            let small = self.small_order();
            let main = self.main_order();
            assert_eq!(small.len(), policy.small.len);
            assert_eq!(main.len(), policy.main.len);
            let young_len = policy
                .small
                .young_tail
                .map(|tail| {
                    small
                        .iter()
                        .position(|slot| *slot == tail)
                        .expect("correlation boundary must belong to Small")
                        + 1
                })
                .unwrap_or(0);
            assert!(young_len <= policy.small.correlation_window);
            assert!(young_len <= policy.small.len);

            let mut resident = HashSet::new();
            for (rank, &slot) in small.iter().enumerate() {
                assert!(resident.insert(slot), "duplicate Small resident {slot}");
                assert!(self.slots[slot].live);
                assert_eq!(policy.slots[slot].location, Location::Small);
                let state = self.bits(slot);
                let young = rank < young_len;
                assert_eq!(state & CORRELATED != 0, young);
                if young {
                    assert_eq!(state, CORRELATED);
                }
                let expected_prev = rank.checked_sub(1).map(|rank| small[rank]);
                let expected_next = small.get(rank + 1).copied();
                assert_eq!(linked(policy.slots[slot].prev), expected_prev);
                assert_eq!(linked(policy.slots[slot].next), expected_next);
            }
            assert_eq!(policy.small.head, small.first().copied());
            assert_eq!(policy.small.tail, small.last().copied());
            let expected_young_tail = young_len
                .checked_sub(1)
                .and_then(|rank| small.get(rank))
                .copied();
            assert_eq!(policy.small.young_tail, expected_young_tail);

            for (rank, &slot) in main.iter().enumerate() {
                assert!(resident.insert(slot), "resident {slot} in two queues");
                assert!(self.slots[slot].live);
                assert_eq!(policy.slots[slot].location, Location::Main);
                assert_eq!(self.bits(slot) & CORRELATED, 0);
                assert_eq!(
                    policy.slots[slot].prev,
                    main[(rank + main.len() - 1) % main.len()]
                );
                assert_eq!(policy.slots[slot].next, main[(rank + 1) % main.len()]);
            }

            for (key, &slot) in &self.index {
                assert!(slot < self.slots.len());
                assert!(resident.contains(&slot));
                assert_eq!(&self.slots[slot].key, key);
            }
            for slot in 0..self.slots.len() {
                if resident.contains(&slot) {
                    assert!(!free.contains(&slot));
                } else {
                    assert!(free.contains(&slot));
                    assert!(!self.slots[slot].live);
                    assert_eq!(policy.slots[slot].location, Location::Free);
                }
            }
            for slot in self.slots.len()..policy.slots.len() {
                assert_eq!(policy.slots[slot].location, Location::Free);
            }

            assert!(policy.ghost.index.len() <= policy.ghost.capacity);
            let ghost = self.ghost_order();
            assert_eq!(ghost.len(), policy.ghost.index.len());
            let ghost_free: HashSet<_> = policy.ghost.free.iter().copied().collect();
            assert_eq!(ghost_free.len(), policy.ghost.free.len());
            let mut seen_ghost = HashSet::new();
            for (rank, &slot) in ghost.iter().enumerate() {
                assert!(seen_ghost.insert(slot));
                assert!(!ghost_free.contains(&slot));
                let key = policy.ghost.slots[slot]
                    .key
                    .as_ref()
                    .expect("linked Ghost entry must have a key");
                assert_eq!(policy.ghost.index.get(key), Some(&slot));
                assert!(!self.index.contains_key(key));
                let expected_prev = rank.checked_sub(1).map(|rank| ghost[rank]);
                let expected_next = ghost.get(rank + 1).copied();
                assert_eq!(linked(policy.ghost.slots[slot].prev), expected_prev);
                assert_eq!(linked(policy.ghost.slots[slot].next), expected_next);
            }
            assert_eq!(policy.ghost.head, ghost.first().copied());
            assert_eq!(policy.ghost.tail, ghost.last().copied());
            for (slot, entry) in policy.ghost.slots.iter().enumerate() {
                if seen_ghost.contains(&slot) {
                    assert!(entry.key.is_some());
                } else {
                    assert!(ghost_free.contains(&slot));
                    assert!(entry.key.is_none());
                }
            }
        }

        /// Asserts both the cache and policy invariants hold.
        fn check_invariants(&self) {
            self.check_cache_invariants();
            self.check_policy_invariants();
        }
    }

    #[test]
    fn test_partitions_round_for_tiny_capacities() {
        // Ratio-derived partitions round down. Capacities above one still keep
        // at least one Small slot, while capacity one uses Main alone.
        let expected = [
            (1, 0, 1, 0, 0),
            (2, 1, 1, 1, 1),
            (10, 1, 9, 1, 5),
            (11, 1, 10, 1, 5),
            (20, 2, 18, 1, 10),
            (40, 4, 36, 2, 20),
        ];
        for (capacity, small, main, window, ghost) in expected {
            let cache = TestCache::<u64, u64>::new(NonZeroUsize::new(capacity).unwrap());
            assert_eq!(cache.policy.small.capacity, small);
            assert_eq!(cache.policy.main.capacity, main);
            assert_eq!(cache.policy.small.correlation_window, window);
            assert_eq!(cache.policy.ghost.capacity, ghost);
            cache.check_invariants();
        }

        // Exercise every tiny partition through repeated replacement, where
        // off-by-one errors in the queue bounds are easiest to expose.
        for capacity in 1..=20 {
            let mut cache = TestCache::new(NonZeroUsize::new(capacity).unwrap());
            for key in 0..200u64 {
                cache.put(key, key);
                cache.check_invariants();
            }
        }
    }

    #[test]
    fn test_capacity_one_behaves_as_clock() {
        // With no Small or Ghost capacity, the only Main slot is replaced on
        // each cold insertion.
        let mut cache = TestCache::new(NZUsize!(1));
        cache.put(1u64, 10u64);
        assert_eq!(cache.get(&1), Some(&10));
        cache.put(2, 20);
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&20));
        assert!(cache.ghost_keys().is_empty());
        cache.check_invariants();
    }

    #[test]
    fn test_warmup_fills_small_then_main_with_cold_entries() {
        // Warm-up fills the 10% Small partition first, then uses the remaining
        // vacant slots for unreferenced Main residents.
        let mut cache = TestCache::new(NZUsize!(20));
        for key in 0..20u64 {
            cache.put(key, key);
        }

        assert_eq!(cache.small_keys(), vec![1, 0]);
        assert_eq!(cache.main_keys(), (2..20).collect::<Vec<_>>());
        for key in 2..20u64 {
            let slot = cache.index[&key];
            assert_eq!(cache.bits(slot) & REFERENCED, 0);
        }
        cache.check_invariants();
    }

    #[test]
    fn test_policy_empty_state_includes_precise_ghost_history() {
        // Resident filtering does not erase unrelated Ghost evidence. The
        // policy may therefore retain useful history with no live residents.
        let mut cache = TestCache::new(NZUsize!(2));
        for key in 1..=3u64 {
            cache.put(key, key);
        }
        assert_eq!(cache.ghost_keys(), vec![1]);

        cache.retain(|key, _| *key == 1);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.ghost_keys(), vec![1]);
        assert!(!cache.policy.ghost.index.is_empty());

        cache.retain(|_, _| false);
        assert_eq!(cache.residents(), 0);
        assert_eq!(cache.ghost_keys(), vec![1]);
        cache.check_invariants();
    }

    #[test]
    fn test_correlation_window_ignores_only_young_hits() {
        // Key 4 is at the Small head, inside the two-entry correlation window.
        // Its hit must not set the bit, so a scan ages and evicts it to Ghost.
        let mut correlated = TestCache::new(NZUsize!(40));
        for key in 1..=40u64 {
            correlated.put(key, key);
        }
        assert_eq!(correlated.small_keys(), vec![4, 3, 2, 1]);
        assert_eq!(correlated.get(&4), Some(&4));
        let slot = correlated.index[&4];
        assert_eq!(correlated.bits(slot) & REFERENCED, 0);
        for key in 41..=44u64 {
            correlated.put(key, key);
        }
        assert!(!correlated.contains(&4));
        assert!(!correlated.main_keys().contains(&4));
        assert!(correlated.ghost_keys().contains(&4));
        correlated.check_invariants();

        // Key 1 is already outside the window. Its hit marks it for promotion
        // to Main when the next insertion examines the Small tail.
        let mut reused = TestCache::new(NZUsize!(40));
        for key in 1..=40u64 {
            reused.put(key, key);
        }
        assert_eq!(reused.get(&1), Some(&1));
        reused.put(41, 41);
        assert!(reused.small_keys().contains(&41));
        assert!(reused.main_keys().contains(&1));
        let slot = reused.index[&1];
        assert_eq!(reused.bits(slot) & REFERENCED, 0);
        assert!(reused.ghost_keys().is_empty());
        reused.check_invariants();
    }

    #[test]
    fn test_removing_younger_entry_does_not_rewind_correlation_age() {
        let mut cache = TestCache::new(NZUsize!(20));
        for key in 0..20u64 {
            cache.put(key, key);
        }

        // Key 0 has left the correlation window, so this hit makes it eligible
        // for promotion when it reaches the Small tail.
        assert_eq!(cache.get(&0), Some(&0));

        // Removing the younger key must not move key 0 back into the
        // correlation window or discard its eligible reference.
        assert!(cache.remove(&1));
        cache.put(20, 20);
        cache.put(21, 21);

        assert!(cache.main_keys().contains(&0));
        assert!(!cache.ghost_keys().contains(&0));
        cache.check_invariants();
    }

    #[test]
    fn test_removing_younger_entry_does_not_delay_correlation_age() {
        let mut cache = TestCache::new(NZUsize!(40));
        for key in 0..40u64 {
            cache.put(key, key);
        }
        assert_eq!(cache.small_keys(), vec![3, 2, 1, 0]);

        // Removing key 3 must not erase its admission from key 2's age. Key 40
        // is the second later Small admission, so key 2 leaves the window.
        assert!(cache.remove(&3));
        cache.put(40, 40);
        assert_eq!(cache.get(&2), Some(&2));

        // Advance key 2 to the Small tail. Its eligible hit must promote it
        // into Main instead of letting the final insertion evict it to Ghost.
        for key in 41..=43u64 {
            cache.put(key, key);
        }
        assert!(cache.main_keys().contains(&2));
        assert!(!cache.ghost_keys().contains(&2));
        cache.check_invariants();
    }

    #[test]
    fn test_ghost_history_is_bounded_and_promotes_reuse() {
        // Cold churn fills the ten-entry Ghost queue and drops its oldest key.
        let mut cache = TestCache::new(NZUsize!(20));
        for key in 0..=30u64 {
            cache.put(key, key);
        }
        assert_eq!(cache.small_keys(), vec![30, 29]);
        assert_eq!(cache.main_keys(), (2..20).collect::<Vec<_>>());
        assert_eq!(
            cache.ghost_keys(),
            (20..=28)
                .rev()
                .chain(core::iter::once(1))
                .collect::<Vec<_>>()
        );

        // Key 1 is still in Ghost, so reuse consumes its history and admits it
        // directly to Main without disturbing Small.
        let (_, value) = cache.get_or_insert_mut(1, || unreachable!());
        *value = 100;
        assert_eq!(cache.peek(&1), Some(&100));
        assert!(cache.main_keys().contains(&1));
        assert!(!cache.ghost_keys().contains(&1));
        assert_eq!(cache.small_keys(), vec![30, 29]);
        assert_eq!(cache.ghost_keys(), (20..=28).rev().collect::<Vec<_>>());

        // Key 0 has already aged out of Ghost and therefore enters Small as a
        // cold miss, evicting Small's tail into Ghost.
        cache.put(0, 200);
        assert_eq!(cache.small_keys()[0], 0);
        assert!(!cache.main_keys().contains(&0));
        assert_eq!(cache.ghost_keys()[0], 29);
        cache.check_invariants();
    }

    #[test]
    fn test_main_evicts_despite_an_offered_vacancy() {
        // Removing the Small resident leaves a globally vacant slot while Main
        // remains full and key 1 remains in Ghost.
        let mut cache = TestCache::new(NZUsize!(2));
        for key in 1..=3u64 {
            cache.put(key, key);
        }
        assert_eq!(cache.main_keys(), vec![2]);
        assert!(cache.remove(&3));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.ghost_keys(), vec![1]);

        // Ghost reuse is constrained to Main, so it replaces Main key 2 and
        // deliberately leaves the Small vacancy unused.
        cache.put(1, 10);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.main_keys(), vec![1]);
        assert!(!cache.contains(&2));
        assert_eq!(cache.free.len(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_promoting_small_replaces_from_full_main() {
        // Reference the original Small tail so the next cold miss promotes it
        // while keeping both fixed-size resident partitions full.
        let mut cache = TestCache::new(NZUsize!(20));
        for key in 0..20u64 {
            cache.put(key, key);
        }
        for key in 0..18u64 {
            assert_eq!(cache.get(&key), Some(&key));
        }
        cache.put(20, 20);
        assert_eq!(cache.policy.main.len, cache.policy.main.capacity);
        assert_eq!(cache.policy.small.len, 2);
        let slot = cache.index[&0];
        assert!(cache.main_keys().contains(&0));
        assert_eq!(cache.bits(slot) & REFERENCED, 0);

        // Repeat the transition with a full Main CLOCK. The promoted key keeps
        // its slot and starts in Main with a clear reference bit.
        let promoted = *cache.small_keys().last().unwrap();
        assert_eq!(cache.get(&promoted), Some(&promoted));
        cache.put(21, 21);

        assert!(cache.main_keys().contains(&promoted));
        let slot = cache.index[&promoted];
        assert_eq!(cache.bits(slot) & REFERENCED, 0);
        assert!(cache.small_keys().contains(&21));
        assert_eq!(cache.policy.main.len, cache.policy.main.capacity);
        assert_eq!(cache.policy.small.len, 2);
        cache.check_invariants();
    }

    #[test]
    fn test_slot_stays_stable_on_promotion_and_goes_stale_on_reuse() {
        // Promotion changes only policy topology, so key 1 keeps its original
        // slot and the existing lookup hint remains valid.
        let mut cache = TestCache::new(NZUsize!(40));
        let (slot1, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (slot2, value) = cache.get_or_insert_mut(2, || 0);
        *value = 20;
        for key in 3..=40u64 {
            cache.put(key, key * 10);
        }
        assert_eq!(cache.get_at(slot1, &1), Some(&10));
        cache.put(41, 410);
        assert_eq!(cache.get_at(slot1, &1), Some(&10));
        assert!(cache.main_keys().contains(&1));

        // An actual eviction reuses key 2's slot for key 42. The old hint then
        // fails full-key validation while the new key resolves in that slot.
        assert!(cache.slots[slot2].live);
        assert_eq!(cache.slots[slot2].key, 2);
        cache.put(42, 420);
        assert_eq!(cache.get_at(slot2, &2), None);
        let slot42 = *cache.index.get(&42).unwrap();
        assert_eq!(slot42, slot2);
        assert_eq!(cache.get_at(slot2, &2), None);
        assert_eq!(cache.get_at(slot42, &42), Some(&420));
        cache.check_invariants();
    }

    #[test]
    fn test_scan_does_not_displace_main() {
        // Warm-up places keys 1 through 9 in Main. A one-cache-capacity scan is
        // absorbed by Small and leaves that Main working set intact.
        let mut clock2qplus = TestCache::new(NZUsize!(10));
        for key in 0..10u64 {
            clock2qplus.put(key, key);
        }
        let mut protected = 1..10u64;
        assert_eq!(clock2qplus.policy.main.len, 9);

        // Plain CLOCK provides the control case and loses every original key
        // to the same scan.
        let mut clock: Cache<u64, u64> = Cache::new(NZUsize!(10));
        for key in 0..10u64 {
            clock.put(key, key);
        }

        for key in 100..110u64 {
            clock2qplus.put(key, key);
            clock.put(key, key);
        }
        assert!(
            protected
                .clone()
                .all(|key| clock2qplus.peek(&key).is_some())
        );
        assert!(protected.all(|key| clock.peek(&key).is_none()));
        clock2qplus.check_invariants();
    }

    #[test]
    fn test_prefill_reuses_values_through_churn() {
        // Prefill allocates every value once. Policy churn must keep reusing
        // those same stable slots without invoking the factory again.
        let mut makes = 0usize;
        let mut cache = TestCache::<u64, Vec<u8>>::new(NZUsize!(20));
        cache.prefill(|| {
            makes += 1;
            vec![0; 32]
        });
        assert_eq!(makes, 20);

        for key in 0..2_000u64 {
            let (_, value) = cache.get_or_insert_mut(key, || unreachable!());
            value[0] = key as u8;
            cache.check_invariants();
        }
        assert_eq!(cache.slots.len(), 20);
        assert_eq!(makes, 20);
    }

    #[test]
    fn test_remove_retain_and_clear_repair_resident_state() {
        // Exercise removal from Main and Ghost, then prove a removed Ghost key
        // returns as cold instead of receiving stale Main admission.
        let mut cache = TestCache::new(NZUsize!(20));
        for key in 0..=30u64 {
            cache.put(key, key);
        }
        cache.put(1, 1);
        assert!(cache.remove(&1));
        assert!(!cache.remove(&1));

        let ghost = cache.ghost_keys()[0];
        assert!(!cache.remove(&ghost));
        assert!(!cache.ghost_keys().contains(&ghost));

        // Replace the vacancy left by the resident removal. With a full cache,
        // the forgotten Ghost key must now enter Small as a cold admission.
        cache.put(100, 100);
        cache.put(ghost, ghost);
        assert!(cache.small_keys().contains(&ghost));
        assert!(!cache.main_keys().contains(&ghost));

        // Retain detaches rejected residents but preserves unrelated Ghost
        // history. Clear resets both resident topology and Ghost history.
        cache.retain(|key, _| key % 2 == 0);
        assert!(!cache.ghost_keys().is_empty());
        assert!(cache.index.keys().all(|key| key % 2 == 0));
        cache.check_invariants();

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.residents(), 0);
        assert!(cache.policy.ghost.index.is_empty());
        assert!(cache.ghost_keys().is_empty());
        cache.check_invariants();
    }

    #[test]
    fn test_shared_hits_are_concurrent() {
        // Shared lookups race only on the relaxed per-slot reference bit. The
        // accumulated hit must still protect key 1 on the next insertion.
        let mut cache = TestCache::new(NZUsize!(40));
        for key in 1..=40u64 {
            cache.put(key, key);
        }
        let slot = *cache.index.get(&1).unwrap();
        let cache = Arc::new(RwLock::new(cache));
        let barrier = Arc::new(Barrier::new(5));
        let mut threads = Vec::new();
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..1_000 {
                    let guard = cache.read();
                    assert_eq!(guard.get_at(slot, &1), Some(&1));
                }
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        let mut cache = Arc::try_unwrap(cache).unwrap().into_inner();
        cache.put(41, 41);
        assert!(cache.main_keys().contains(&1));
        cache.check_invariants();
    }

    #[test]
    fn test_fallible_factory_error_leaves_policy_unchanged() {
        // Key 1 is in Ghost. A failed factory must return before policy
        // insertion consumes that evidence or changes resident topology.
        let mut cache = TestCache::new(NZUsize!(2));
        for key in 1..=3u64 {
            cache.put(key, key);
        }
        let small = cache.small_keys();
        let main = cache.main_keys();
        let ghost = cache.ghost_keys();
        let result = cache.try_get_or_insert_with(1, || Err::<u64, _>("failure"));
        assert_eq!(result, Err("failure"));
        assert_eq!(cache.small_keys(), small);
        assert_eq!(cache.main_keys(), main);
        assert_eq!(cache.ghost_keys(), ghost);
        cache.check_invariants();
    }

}
