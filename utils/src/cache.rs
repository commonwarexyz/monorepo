//! A fixed-capacity key-value cache using [Clock2Q+](https://arxiv.org/abs/2511.21958) replacement.
//!
//! Clock2Q+ separates residents into a Small probation queue and a Main CLOCK
//! ring. New entries enter Small, where hits outside a correlation window earn
//! promotion to Main. Main gives referenced entries a second chance before
//! eviction. A bounded Ghost queue records keys evicted from Small. A later
//! request for one of these keys consumes its history and enters Main directly.
//! During warm-up, cold entries fill Small first and then Main.
//!
//! For capacity `C`, Small is `max(C / 10, 1)` when `C > 1`, Main gets the
//! remainder, and Ghost is `C / 2`. The newest half of Small, rounded up, forms
//! the correlation window. Hits inside this window are ignored. Admission age
//! advances even when entries are removed, so older survivors never become
//! young again. At capacities 2 through 19, Small holds one always-correlated
//! slot, so admission to a full Main requires a Ghost hit. Capacity one uses
//! Main alone.
//!
//! # Stable Slots and Hints
//!
//! A resident keeps its numeric slot until removal or eviction, including when
//! it moves from Small to Main. [Cache::get_at] validates both liveness and the
//! full key. Stale or out-of-bounds hints therefore return a miss, and callers
//! can fall back to [Cache::get].
//!
//! # Value Reuse
//!
//! Slots grow lazily to capacity and are then reused in place. [Cache::remove]
//! and [Cache::retain] keep detached values available for later insertion.
//! [Cache::get_or_insert_mut] returns the selected slot and its existing value
//! so pooled buffers can be overwritten without reallocating. [Cache::prefill]
//! can allocate every value during construction. Value-returning methods such
//! as [Cache::put] replace and drop displaced values as usual.
//!
//! Resident and Ghost indexes store only slot IDs and read canonical keys from
//! their respective slots. Each index reserves twice its independent entry
//! limit, keeping its backing allocation fixed during insertion and eviction.
//! Tombstone cleanup can still rehash the indexes in place. Keys, values, and
//! other metadata can allocate separately.
//!
//! # Concurrency
//!
//! [Cache] performs no internal locking. Shared lookups record hits in an inline
//! atomic byte without accessing queue topology. Mutating operations require
//! `&mut self`, so a reader-writer lock can serve hits concurrently:
//!
//! ```
//! use commonware_utils::cache::Cache;
//! use core::num::NonZeroUsize;
//! use std::sync::RwLock;
//!
//! let cache = RwLock::new(Cache::<u64, u64>::new(NonZeroUsize::new(4).unwrap()));
//! if cache.read().unwrap().get(&7).is_none() {
//!     cache.write().unwrap().get_or_insert_with(7, || 7 * 7);
//! }
//! assert_eq!(cache.read().unwrap().get(&7).copied(), Some(49));
//! ```

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{
    hash::Hash,
    num::NonZeroUsize,
    sync::atomic::{AtomicU8, Ordering},
};
use hashbrown::HashTable;

/// Shared hashing state for resident and Ghost indexes.
type Hasher = ahash::RandomState;

/// Stable identifier for cache storage.
type Slot = usize;

/// A single cache slot.
///
/// A slot is live when its key is present in the index, and free otherwise.
/// Free slots keep their (now stale) `key` and `value` until the slot is reused,
/// with `live` cleared so [Cache::get_at] cannot resolve them.
struct Entry<K, V> {
    key: K,
    value: V,
    state: SlotState,
    live: bool,
}

/// A fixed-capacity key-value cache using Clock2Q+ replacement.
///
/// Keys must keep the same [Hash] and [Eq] identity throughout each cache
/// operation, including value factories and other callbacks, and while resident
/// or retained in Ghost history. Violating this requirement is a logic error
/// and may cause incorrect lookups or admission decisions.
pub struct Cache<K, V> {
    /// Resident membership. Each indexed slot owns its canonical key.
    /// Twice the resident limit allows tombstone cleanup without growing.
    index: HashTable<Slot>,
    /// Shared hashing state for resident and Ghost indexes.
    hasher: Hasher,
    /// Stable keys, reusable values, and inline shared-hit state.
    slots: Vec<Entry<K, V>>,
    /// Slots detached by remove/retain or prepared by prefill.
    free: Vec<Slot>,
    /// Maximum number of residents.
    capacity: usize,
    /// Cold queue links and admission ages indexed by stable slot identity.
    topology: Vec<ResidentSlot>,
    /// Admission queue and correlation-window state.
    small: SmallQueue,
    /// Eviction ring and CLOCK hand.
    main: MainRing,
    /// Exact bounded history of keys evicted from Small.
    ghost: GhostQueue<K>,
}

impl<K: Hash + Eq, V> Cache<K, V> {
    /// Creates an empty cache with room for `capacity` residents.
    pub fn new(capacity: NonZeroUsize) -> Self {
        let capacity = capacity.get();
        let small_capacity = if capacity == 1 {
            0
        } else {
            (capacity / 10).max(1)
        };
        Self {
            index: HashTable::with_capacity(capacity.checked_mul(2).expect("capacity overflow")),
            hasher: Hasher::default(),
            slots: Vec::with_capacity(capacity),
            free: Vec::new(),
            capacity,
            topology: vec![ResidentSlot::default(); capacity],
            small: SmallQueue::new(small_capacity),
            main: MainRing::new(capacity - small_capacity),
            ghost: GhostQueue::new(capacity / 2),
        }
    }

    /// Returns the maximum number of entries the cache can hold.
    #[inline]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of entries currently in the cache.
    #[inline]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Returns `true` if the cache holds no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Returns `true` if `key` is in the cache without recording use.
    #[inline]
    pub fn contains(&self, key: &K) -> bool {
        self.find_slot(key).is_some()
    }

    /// Returns a reference to the value for `key` without recording use.
    ///
    /// Unlike [Self::get], this does not affect replacement decisions.
    #[inline]
    pub fn peek(&self, key: &K) -> Option<&V> {
        let slot = self.find_slot(key)?;
        Some(&self.slots[slot].value)
    }

    /// Returns a reference to the value for `key`, recording use.
    ///
    /// This takes `&self` so it can be called concurrently behind a shared lock.
    /// Hits update only relaxed atomic replacement metadata.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        let index = self.find_slot(key)?;
        let slot = &self.slots[index];
        slot.state.record_hit();
        Some(&slot.value)
    }

    /// Returns a reference to the value in `slot` if that slot currently holds
    /// `key` as a live entry, recording use.
    ///
    /// This is the read half of an external slot index: callers that recorded a
    /// key's slot (via [Self::get_or_insert_mut]) can resolve it with a
    /// key compare instead of a hash lookup. Any stale index entry reads as a
    /// miss rather than a wrong value: a slot reused for another key fails the
    /// key compare, a slot freed by [Self::remove] or [Self::retain] is not
    /// live, and an out-of-range slot does not exist. External indexes
    /// therefore need no maintenance beyond tolerating misses.
    #[inline]
    pub fn get_at(&self, slot: usize, key: &K) -> Option<&V> {
        let resident = self.slots.get(slot)?;
        if !resident.live || resident.key != *key {
            return None;
        }

        resident.state.record_hit();
        Some(&resident.value)
    }

    /// Returns a mutable reference to the value for `key`, recording use.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let index = self.find_slot(key)?;
        let slot = &mut self.slots[index];
        slot.state.record_hit_mut();
        Some(&mut slot.value)
    }

    /// Inserts `value` for `key`.
    ///
    /// If `key` was already present, replaces and returns the previous value,
    /// recording use. Otherwise claims vacant capacity or selects a
    /// resident to evict.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.hasher.hash_one(&key);
        if let Some(index) = self.find_slot_hashed(&key, hash) {
            let slot = &mut self.slots[index];
            slot.state.record_hit_mut();
            return Some(core::mem::replace(&mut slot.value, value));
        }
        self.insert(key, hash, Some(value), || unreachable!());
        None
    }

    /// Returns the value for `key`, computing and inserting it with `f` on a
    /// miss.
    ///
    /// On a hit, `f` is not called. On a miss, `f` is called, its result is
    /// inserted (evicting a resident if necessary), and a reference
    /// to the stored value is returned.
    pub fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, f: F) -> &V {
        let hash = self.hasher.hash_one(&key);
        let slot = match self.find_slot_hashed(&key, hash) {
            Some(slot) => {
                self.slots[slot].state.record_hit_mut();
                slot
            }
            None => self.insert(key, hash, Some(f()), || unreachable!()),
        };
        &self.slots[slot].value
    }

    /// Returns the value for `key`, computing and inserting it with a fallible
    /// `f` on a miss.
    ///
    /// On a hit, `f` is not called. On a miss, `f` is called; if it returns an
    /// error the error is propagated and nothing is inserted, so failures are
    /// not cached.
    pub fn try_get_or_insert_with<F: FnOnce() -> Result<V, E>, E>(
        &mut self,
        key: K,
        f: F,
    ) -> Result<&V, E> {
        let hash = self.hasher.hash_one(&key);
        let slot = match self.find_slot_hashed(&key, hash) {
            Some(slot) => {
                self.slots[slot].state.record_hit_mut();
                slot
            }
            None => self.insert(key, hash, Some(f()?), || unreachable!()),
        };
        Ok(&self.slots[slot].value)
    }

    /// Returns the slot index and a mutable reference to the slot for `key`,
    /// reusing an existing allocation where possible.
    ///
    /// On a hit, records use and returns the current value. On a miss into a
    /// reused slot (a freed slot or an eviction victim), the returned reference
    /// is the reused slot's stale value, which the caller is expected to
    /// overwrite. Only when the cache grows is `make` called to produce a fresh
    /// value. This lets callers holding pooled buffers overwrite in place
    /// rather than allocating on every insert.
    ///
    /// The slot index identifies the entry until it is evicted or removed, so
    /// callers can record it in an external index and resolve later reads with
    /// [Self::get_at] instead of a hash lookup.
    pub fn get_or_insert_mut<F: FnOnce() -> V>(&mut self, key: K, make: F) -> (usize, &mut V) {
        let hash = self.hasher.hash_one(&key);
        let slot = match self.find_slot_hashed(&key, hash) {
            Some(slot) => {
                self.slots[slot].state.record_hit_mut();
                slot
            }
            None => self.insert(key, hash, None, make),
        };
        (slot, &mut self.slots[slot].value)
    }

    /// Removes `key`, returning whether it was present.
    ///
    /// The slot and its allocation are retained for reuse, so the value is not
    /// returned. If the key is not resident, its Ghost history is forgotten.
    pub fn remove(&mut self, key: &K) -> bool {
        let hash = self.hasher.hash_one(key);
        match self
            .index
            .find_entry(hash, |&slot| self.slots[slot].key == *key)
        {
            Ok(entry) => {
                let slot = entry.remove().0;
                self.unlink_resident(slot);
                self.slots[slot].live = false;
                self.free.push(slot);
                true
            }
            Err(_) => {
                self.ghost.discard(key, hash);
                false
            }
        }
    }

    /// Retains only the entries for which `keep` returns `true`.
    ///
    /// Dropped entries' slots and allocations are retained for reuse.
    /// Unrelated Ghost history is preserved.
    pub fn retain<F: FnMut(&K, &V) -> bool>(&mut self, mut keep: F) {
        let Self {
            index,
            slots,
            free,
            topology,
            small,
            main,
            ..
        } = self;
        index.retain(|&mut slot| {
            let resident = &mut slots[slot];
            let keep = keep(&resident.key, &resident.value);
            if !keep {
                match topology[slot].location() {
                    Location::Small => small.unlink(topology, slot),
                    Location::Main => main.unlink(topology, slot),
                    Location::Free => unreachable!("resident slot cannot be free"),
                }
                resident.live = false;
                free.push(slot);
            }
            keep
        });
    }

    /// Removes all entries, dropping their values and retaining the allocated
    /// capacity of the indexes and slot vectors.
    pub fn clear(&mut self) {
        self.index.clear();
        self.free.clear();
        self.topology.fill(ResidentSlot::default());
        self.small.clear();
        self.main.clear();
        self.slots.clear();
        self.ghost.clear();
    }

    #[inline]
    fn find_slot(&self, key: &K) -> Option<Slot> {
        self.find_slot_hashed(key, self.hasher.hash_one(key))
    }

    #[inline]
    fn find_slot_hashed(&self, key: &K, hash: u64) -> Option<Slot> {
        self.index
            .find(hash, |&slot| self.slots[slot].key == *key)
            .copied()
    }

    /// Publishes a slot after its canonical key is installed. All indexed slots
    /// retain their keys while insertion may rehash the table.
    #[inline]
    fn index_slot(&mut self, slot: Slot, hash: u64) {
        let slots = &self.slots;
        let hasher = &self.hasher;
        let _ = self
            .index
            .insert_unique(hash, slot, |&slot| hasher.hash_one(&slots[slot].key));
    }

    /// Installs an absent key, replacing a supplied value or reusing storage.
    /// `make` supplies a value only when a reusable value is unavailable.
    fn insert<F: FnOnce() -> V>(&mut self, key: K, hash: u64, value: Option<V>, make: F) -> Slot {
        let ghost_hit = self.ghost.discard(&key, hash);
        let has_vacancy = !self.free.is_empty() || self.slots.len() < self.capacity;
        let admission = self.admission(ghost_hit, has_vacancy);
        let plan = self.plan(admission, has_vacancy);

        // Remove the resident index while its canonical victim key is still
        // installed. The same hash accompanies a Small key into Ghost.
        let (slot, historical_hash) = if let Some(victim) = plan.victim() {
            let victim_hash = self.hasher.hash_one(&self.slots[victim].key);
            self.index
                .find_entry(victim_hash, |&slot| slot == victim)
                .expect("a live victim must be indexed")
                .remove();
            let location = self.unlink_resident(victim);
            (victim, (location == Location::Small).then_some(victim_hash))
        } else {
            (self.free.pop().unwrap_or(self.slots.len()), None)
        };

        if let InsertionPlan::PromoteThenEvict { promoted, .. } = plan {
            self.small.unlink(&mut self.topology, promoted);
            self.slots[promoted].state.reset();
            self.main.push(&mut self.topology, promoted);
        }

        let state = SlotState::new(admission);
        let (displaced_key, displaced_value) = if slot == self.slots.len() {
            self.slots.push(Entry {
                key,
                value: value.unwrap_or_else(make),
                state,
                live: true,
            });
            (None, None)
        } else {
            let entry = &mut self.slots[slot];
            let displaced_key = core::mem::replace(&mut entry.key, key);
            let displaced_value = value.map(|value| core::mem::replace(&mut entry.value, value));
            entry.state = state;
            entry.live = true;
            (Some(displaced_key), displaced_value)
        };

        match admission {
            Admission::Small => self.small.push(&self.slots, &mut self.topology, slot),
            Admission::Main => self.main.push(&mut self.topology, slot),
        }
        self.index_slot(slot, hash);

        // Bookkeeping is complete before destructors can run. Small victims
        // transfer their owned key. Main and free-slot keys have no history.
        if let Some(victim_hash) = historical_hash {
            self.ghost.push(
                displaced_key.expect("victim must own a key"),
                victim_hash,
                &self.hasher,
            );
        } else {
            drop(displaced_key);
        }
        drop(displaced_value);
        slot
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
    fn plan(&mut self, admission: Admission, has_vacancy: bool) -> InsertionPlan {
        match admission {
            Admission::Small if has_vacancy => InsertionPlan::Vacant,
            Admission::Small => {
                let tail = self.small.tail.expect("full cache must have a Small tail");
                if !self.slots[tail].state.earned_promotion() {
                    return InsertionPlan::Evict { victim: tail };
                }

                // A full cache and bounded partitions imply Main is also full.
                // Promote the referenced Small tail while the incoming entry
                // reuses the Main victim selected here.
                assert_eq!(self.main.len, self.main.capacity);
                let victim = self.main.select(&self.slots, &self.topology);
                InsertionPlan::PromoteThenEvict {
                    promoted: tail,
                    victim,
                }
            }
            Admission::Main if self.main.len == self.main.capacity => InsertionPlan::Evict {
                victim: self.main.select(&self.slots, &self.topology),
            },
            Admission::Main => {
                // Main can grow only while the cache has unused capacity.
                assert!(has_vacancy);
                InsertionPlan::Vacant
            }
        }
    }

    /// Detaches a resident and returns its previous partition.
    #[inline]
    fn unlink_resident(&mut self, slot: Slot) -> Location {
        let location = self.topology[slot].location();
        match location {
            Location::Small => self.small.unlink(&mut self.topology, slot),
            Location::Main => self.main.unlink(&mut self.topology, slot),
            Location::Free => unreachable!("resident slot cannot be free"),
        }
        location
    }
}

impl<K: Hash + Eq + Default, V> Cache<K, V> {
    /// Pre-allocates all slots up to capacity, each holding a value from `make`,
    /// and leaves them free for reuse.
    ///
    /// After this call, the first `capacity` inserts reuse a pre-allocated slot
    /// instead of growing, so `make` (and any allocation it performs) runs only
    /// here. Use this to front-load value allocation at construction so
    /// steady-state inserts never allocate values. Free slots are seeded with the
    /// default key as a throwaway placeholder that is overwritten when the slot
    /// is first filled.
    pub fn prefill<F: FnMut() -> V>(&mut self, mut make: F) {
        let start = self.free.len();
        while self.slots.len() < self.capacity {
            let slot = self.slots.len();
            self.slots.push(Entry {
                key: K::default(),
                value: make(),
                state: SlotState::default(),
                live: false,
            });
            self.free.push(slot);
        }

        // The free list pops from the back, so reverse the new entries to hand
        // them out in ascending slot order (matching how growth assigns slots).
        self.free[start..].reverse();
    }
}

impl<K, V> core::fmt::Debug for Cache<K, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cache")
            .field("len", &self.index.len())
            .field("capacity", &self.capacity)
            .field("small", &self.small.len)
            .field("small_capacity", &self.small.capacity)
            .field("main", &self.main.len)
            .field("main_capacity", &self.main.capacity)
            .field("ghost", &self.ghost.index.len())
            .field("ghost_capacity", &self.ghost.capacity)
            .finish()
    }
}

/// Sentinel used when a cache-owned slot has no neighbor.
const UNLINKED: usize = usize::MAX;
/// Low bits available for the modular Small admission generation.
const ADMISSION_GENERATION_MASK: usize = usize::MAX >> 2;
/// Bit offset of the resident location tag.
const LOCATION_SHIFT: u32 = usize::BITS - 2;
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

impl Location {
    const fn pack(self, admission_generation: usize) -> usize {
        let tag = match self {
            Self::Free => 0,
            Self::Small => 1,
            Self::Main => 2,
        };
        (tag << LOCATION_SHIFT) | (admission_generation & ADMISSION_GENERATION_MASK)
    }
}

/// Cold topology for a stable cache slot.
#[derive(Clone, Copy)]
struct ResidentSlot {
    /// Previous entry toward the head of Small, or in Main's circular ring.
    prev: usize,
    /// Next entry toward the tail of Small, or in Main's circular ring.
    next: usize,
    /// Location tag in the high bits and Small admission generation in the low bits.
    location_and_admission: usize,
}

impl ResidentSlot {
    #[inline]
    const fn has_location(&self, location: Location) -> bool {
        self.location_and_admission & !ADMISSION_GENERATION_MASK == location.pack(0)
    }

    #[inline]
    fn location(&self) -> Location {
        match self.location_and_admission >> LOCATION_SHIFT {
            0 => Location::Free,
            1 => Location::Small,
            2 => Location::Main,
            _ => unreachable!("invalid resident location tag"),
        }
    }

    const fn admitted_at(&self) -> usize {
        self.location_and_admission & ADMISSION_GENERATION_MASK
    }
}

impl Default for ResidentSlot {
    fn default() -> Self {
        Self {
            prev: UNLINKED,
            next: UNLINKED,
            location_and_admission: Location::Free.pack(0),
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
    /// Use unused cache capacity.
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

/// Replacement state stored inline with each cache slot.
///
/// The correlation marker and reference bit share one atomic byte, so a shared
/// hit needs no access to cache-owned queue topology. Relaxed ordering is
/// sufficient because these bits affect only replacement decisions and do not
/// publish resident keys or values.
#[repr(transparent)]
#[derive(Default)]
struct SlotState(AtomicU8);

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
        if *current & (CORRELATED | REFERENCED) == 0 {
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
    /// Modular count of Small admissions, including removed entries.
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
    fn push<K, V>(&mut self, entries: &[Entry<K, V>], slots: &mut [ResidentSlot], slot: Slot) {
        // Admission count, rather than live queue length, preserves correlation
        // age across explicit removal and retention. A correlated resident leaves
        // within one bounded window, long before the generation counter wraps.
        self.admissions = self.admissions.wrapping_add(1) & ADMISSION_GENERATION_MASK;
        let old_head = self.head;
        {
            let entry = &mut slots[slot];
            assert!(entry.has_location(Location::Free));
            entry.prev = UNLINKED;
            entry.next = old_head.unwrap_or(UNLINKED);
            entry.location_and_admission = Location::Small.pack(self.admissions);
        }
        if let Some(head) = old_head {
            slots[head].prev = slot;
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);
        self.len += 1;

        // Only the oldest correlated survivor can leave the window after one
        // new admission because Small preserves admission order.
        let demoted = *self.young_tail.get_or_insert(slot);
        let age =
            self.admissions.wrapping_sub(slots[demoted].admitted_at()) & ADMISSION_GENERATION_MASK;
        if age < self.correlation_window {
            return;
        }

        let new_boundary = slots[demoted].prev;
        assert_ne!(new_boundary, UNLINKED);

        // Discard references made inside the correlation window. Only a hit
        // after the entry becomes old should promote it to Main.
        entries[demoted].state.reset();
        slots[demoted].location_and_admission = Location::Small.pack(0);
        self.young_tail = Some(new_boundary);
    }

    /// Detaches a resident and repairs the queue and correlation boundary.
    #[inline]
    fn unlink(&mut self, slots: &mut [ResidentSlot], slot: Slot) {
        assert!(slots[slot].has_location(Location::Small));
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
    fn select<K, V>(&mut self, entries: &[Entry<K, V>], slots: &[ResidentSlot]) -> Slot {
        loop {
            let slot = self.hand.expect("nonempty Main must have a hand");
            if entries[slot].state.take_reference() {
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
            assert!(entry.has_location(Location::Free));
            entry.prev = slot;
            entry.next = slot;
            entry.location_and_admission = Location::Main.pack(0);
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
            assert!(entry.has_location(Location::Free));
            entry.prev = prev;
            entry.next = hand;
            entry.location_and_admission = Location::Main.pack(0);
        }
        slots[prev].next = slot;
        slots[hand].prev = slot;
        self.len += 1;
    }

    /// Detaches a resident and advances the hand when necessary.
    #[inline]
    fn unlink(&mut self, slots: &mut [ResidentSlot], slot: Slot) {
        assert!(slots[slot].has_location(Location::Main));
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
    /// Previous entry toward the Ghost head, or `UNLINKED` when free.
    prev: usize,
    /// Next entry toward the Ghost tail, or the next free slot when `key` is `None`.
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
    /// Exact key membership represented by queue positions.
    ///
    /// Twice the history bound keeps live entries within half the usable
    /// capacity, where hashbrown reclaims tombstones in place without growing.
    /// Both indexes use the cache's single randomized hashing state.
    index: HashTable<usize>,
    /// Storage for linked historical entries.
    slots: Vec<GhostSlot<K>>,
    /// First detached position, linked through [GhostSlot::next].
    free_head: Option<usize>,
    /// Newest historical entry.
    head: Option<usize>,
    /// Oldest historical entry.
    tail: Option<usize>,
    /// Maximum number of historical entries.
    capacity: usize,
}

impl<K: Hash + Eq> GhostQueue<K> {
    /// Constructs empty exact history bounded by `capacity`.
    fn new(capacity: usize) -> Self {
        Self {
            index: HashTable::with_capacity(capacity.checked_mul(2).expect("capacity overflow")),
            slots: Vec::with_capacity(capacity),
            free_head: None,
            head: None,
            tail: None,
            capacity,
        }
    }

    /// Adds an evicted Small key at the queue head.
    #[inline]
    fn push(&mut self, key: K, hash: u64, hasher: &Hasher) {
        if self.capacity == 0 {
            return;
        }

        // Prefer recycled storage, then grow to the Ghost bound, then reuse
        // the oldest live slot after removing its previous key.
        let mut displaced = None;
        let slot = if let Some(slot) = self.free_head {
            self.free_head = linked(self.slots[slot].next);
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

            // The table's slot index is valid only while this canonical key is
            // live. Remove the index entry before unlinking and dropping it.
            let historical_hash = hasher.hash_one(
                self.slots[slot]
                    .key
                    .as_ref()
                    .expect("linked Ghost entry must have a key"),
            );
            self.index
                .find_entry(historical_hash, |candidate| *candidate == slot)
                .expect("linked Ghost entry must be indexed")
                .remove();
            displaced = Some(self.unlink(slot));
            slot
        };

        let old_head = self.head;
        {
            let entry = &mut self.slots[slot];
            assert!(entry.key.is_none());
            entry.key = Some(key);
            entry.prev = UNLINKED;
            entry.next = old_head.unwrap_or(UNLINKED);
        }
        if let Some(head) = old_head {
            self.slots[head].prev = slot;
        } else {
            self.tail = Some(slot);
        }
        self.head = Some(slot);

        // Resident and Ghost keys are disjoint. Every indexed slot owns a live
        // key, including while insertion rehashes the table.
        let slots = &self.slots;
        let _ = self.index.insert_unique(hash, slot, |slot| {
            hasher.hash_one(
                slots[*slot]
                    .key
                    .as_ref()
                    .expect("indexed Ghost entry must have a key"),
            )
        });
        drop(displaced);
    }

    /// Removes exact history for `key` and reports whether it was present.
    #[inline]
    fn discard(&mut self, key: &K, hash: u64) -> bool {
        let slot = {
            let slots = &self.slots;
            let Ok(entry) = self.index.find_entry(hash, |slot| {
                slots[*slot]
                    .key
                    .as_ref()
                    .expect("indexed Ghost entry must have a key")
                    == key
            }) else {
                return false;
            };
            entry.remove().0
        };
        // Recycle the position before dropping the key, so a panicking
        // destructor cannot strand the detached slot outside the free list.
        let historical = self.unlink(slot);
        self.slots[slot].next = self.free_head.unwrap_or(UNLINKED);
        self.free_head = Some(slot);
        drop(historical);
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
        self.free_head = None;
        self.head = None;
        self.tail = None;
        self.slots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NZUsize, sync::RwLock};
    use core::cell::{Cell, RefCell};
    use proptest::{prelude::*, test_runner::TestCaseResult};
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        rc::Rc,
        sync::{Arc, Barrier},
        thread,
    };

    #[test]
    fn test_basic_put_get_peek() {
        let mut cache = Cache::new(NZUsize!(2));
        assert!(cache.is_empty());
        assert_eq!(cache.capacity(), 2);

        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(2, 20), None);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&1).copied(), Some(10));
        assert_eq!(cache.peek(&2).copied(), Some(20));
        assert!(cache.contains(&1));
        assert!(!cache.contains(&3));
        assert_eq!(cache.get(&3), None);
        cache.check_invariants();
    }

    #[test]
    fn test_put_replaces_existing() {
        let mut cache = Cache::new(NZUsize!(2));
        assert_eq!(cache.put(1u64, 10u64), None);
        assert_eq!(cache.put(1, 11), Some(10));
        assert_eq!(cache.get(&1).copied(), Some(11));
        assert_eq!(cache.len(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_capacity_one_reuses_its_only_slot() {
        let mut cache = Cache::new(NZUsize!(1));
        cache.put(1u64, 10u64);
        cache.put(2, 20);
        assert!(!cache.contains(&1));
        assert_eq!(cache.get(&2).copied(), Some(20));
        assert_eq!(cache.len(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_get_or_insert_with_calls_factory_only_on_miss() {
        let mut cache = Cache::new(NZUsize!(2));
        let calls = Cell::new(0);
        let compute = |key: u64| {
            calls.set(calls.get() + 1);
            key * 100
        };

        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        // A hit does not call the factory.
        assert_eq!(*cache.get_or_insert_with(1, || compute(1)), 100);
        assert_eq!(calls.get(), 1);
        cache.check_invariants();
    }

    #[test]
    fn test_try_get_or_insert_with_does_not_cache_errors() {
        let mut cache = Cache::new(NZUsize!(2));

        let error: Result<&u64, &str> = cache.try_get_or_insert_with(1u64, || Err("bad"));
        assert_eq!(error, Err("bad"));
        assert!(!cache.contains(&1));

        let value: Result<&u64, &str> = cache.try_get_or_insert_with(1, || Ok(10));
        assert_eq!(value, Ok(&10));
        assert!(cache.contains(&1));
        cache.check_invariants();
    }

    #[test]
    fn test_remove_keeps_slot_for_reuse() {
        // A removed entry frees its slot for reuse without growing the slot
        // vector or calling the factory again.
        let makes = Cell::new(0);
        let mut cache = Cache::new(NZUsize!(2));
        cache.get_or_insert_mut(1, || {
            makes.set(makes.get() + 1);
            10
        });
        cache.get_or_insert_mut(2, || {
            makes.set(makes.get() + 1);
            20
        });
        assert_eq!(makes.get(), 2);
        assert_eq!(cache.slots.len(), 2);

        assert!(cache.remove(&1));
        assert!(!cache.contains(&1));
        assert_eq!(cache.len(), 1);

        // Reusing the freed slot does not call the factory or grow.
        *cache
            .get_or_insert_mut(3, || {
                makes.set(makes.get() + 1);
                30
            })
            .1 = 30;

        assert_eq!(makes.get(), 2, "freed slot should not call the factory");
        assert_eq!(cache.slots.len(), 2);
        assert_eq!(cache.get(&3).copied(), Some(30));
        assert!(!cache.remove(&999));
        cache.check_invariants();
    }

    #[test]
    fn test_retain_frees_slots_for_reuse() {
        let mut cache = Cache::new(NZUsize!(4));
        for key in 0..4u64 {
            cache.put(key, key * 10);
        }
        // Keep even keys.
        cache.retain(|key, _| key % 2 == 0);
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&0));
        assert!(cache.contains(&2));
        assert!(!cache.contains(&1));
        assert!(!cache.contains(&3));

        // Freed slots are reused for new inserts.
        cache.put(10, 100);
        cache.put(12, 120);
        assert_eq!(cache.slots.len(), 4);
        assert_eq!(cache.len(), 4);
        cache.check_invariants();
    }

    #[test]
    fn test_get_or_insert_mut_reuses_allocations() {
        // The factory runs at most `capacity` times no matter how many distinct
        // keys churn through the cache, proving evicted slots are reused.
        let makes = Cell::new(0);
        let mut cache = Cache::new(NZUsize!(3));
        for key in 0..100u64 {
            let (_, value) = cache.get_or_insert_mut(key, || {
                makes.set(makes.get() + 1);
                0
            });
            *value = key; // Overwrite the possibly stale reused value.
        }
        assert_eq!(makes.get(), 3, "factory should run only during growth");
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_invariants();
    }

    #[test]
    fn test_prefill_allocates_once_and_reuses() {
        // Prefill runs the factory exactly `capacity` times. Subsequent inserts
        // reuse pre-allocated slots without growing or calling the factory.
        let makes = Cell::new(0);
        let mut cache = Cache::new(NZUsize!(3));
        cache.prefill(|| {
            makes.set(makes.get() + 1);
            0
        });
        assert_eq!(makes.get(), 3);
        assert_eq!(cache.slots.len(), 3);
        assert!(cache.is_empty());
        cache.check_invariants();

        // Churn many keys without further factory calls or slot growth.
        for key in 0..100u64 {
            *cache
                .get_or_insert_mut(key, || {
                    makes.set(makes.get() + 1);
                    0
                })
                .1 = key;
        }
        assert_eq!(makes.get(), 3, "prefilled slots must be reused");
        assert_eq!(cache.slots.len(), 3);
        assert_eq!(cache.len(), 3);
        cache.check_invariants();
    }

    #[test]
    fn test_prefill_and_detached_slots_preserve_reuse_order() {
        for interrupted in [false, true] {
            let mut cache = Cache::<u64, u64>::new(NZUsize!(6));
            for key in 0..3 {
                assert_eq!(cache.get_or_insert_mut(key, || key + 10).0, key as usize);
            }
            assert!(cache.remove(&1));
            assert!(cache.remove(&2));

            let mut next = 3;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cache.prefill(|| {
                    assert!(!interrupted || next != 5, "prefill factory panic");
                    let value = next + 10;
                    next += 1;
                    value
                });
            }));
            assert_eq!(result.is_err(), interrupted);
            assert_eq!(cache.get_at(0, &0), Some(&10));
            cache.check_invariants();

            // Successful prefill yields new slots in creation order. An interrupted
            // prefill leaves completed slots on top of the existing free stack.
            let expected: &[usize] = if interrupted {
                &[4, 3, 2, 1]
            } else {
                &[3, 4, 5, 2, 1]
            };
            for &expected_slot in expected {
                let (slot, value) =
                    cache.get_or_insert_mut(expected_slot as u64, || unreachable!());
                assert_eq!(slot, expected_slot);
                assert_eq!(*value, expected_slot as u64 + 10);
                cache.check_invariants();
            }
            if interrupted {
                assert_eq!(cache.get_or_insert_mut(5, || 15).0, 5);
            }

            assert!(cache.remove(&1));
            assert!(cache.remove(&2));
            let mut detached = vec![1, 2];
            cache.retain(|key, _| {
                if *key == 0 || *key == 3 {
                    detached.push(*key as usize);
                    false
                } else {
                    true
                }
            });
            cache.check_invariants();
            for expected_slot in detached.into_iter().rev() {
                let (slot, value) =
                    cache.get_or_insert_mut(expected_slot as u64 + 20, || unreachable!());
                assert_eq!(slot, expected_slot);
                assert_eq!(*value, expected_slot as u64 + 10);
                cache.check_invariants();
            }
        }
    }

    #[test]
    fn test_clear_drops_entries_and_allows_reuse() {
        let mut cache = Cache::new(NZUsize!(4));
        for key in 0..4u64 {
            cache.put(key, key);
        }
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        cache.put(9, 9);
        assert_eq!(cache.get(&9).copied(), Some(9));
        cache.check_invariants();
    }

    #[derive(Clone)]
    struct Tracked(Rc<Cell<usize>>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn test_values_are_dropped_on_replacement_and_clear() {
        let drops = Rc::new(Cell::new(0));
        let mut cache = Cache::new(NZUsize!(2));
        for key in 0..2u64 {
            cache.put(key, Tracked(drops.clone()));
        }
        assert_eq!(drops.get(), 0);

        // Inserting a third entry evicts one and drops its value.
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);

        // Replacing an existing key drops the old value.
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 2);

        // Clearing drops the remaining two values.
        cache.clear();
        assert_eq!(drops.get(), 4);
    }

    #[test]
    fn test_remove_retains_value_until_reuse() {
        // remove does not drop the value. The freed slot keeps it until a
        // value-inserting method reuses the slot.
        let drops = Rc::new(Cell::new(0));
        let mut cache = Cache::new(NZUsize!(2));
        cache.put(1, Tracked(drops.clone()));
        assert!(cache.remove(&1));
        assert_eq!(drops.get(), 0, "remove must not drop the value");

        // Reusing the freed slot through a value insert drops the retained value.
        cache.put(2, Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn test_get_at_validates_key() {
        let mut cache = Cache::new(NZUsize!(2));
        let (first, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (second, value) = cache.get_or_insert_mut(2u64, || 0u64);
        *value = 20;

        // A recorded slot resolves with a key comparison and no hash lookup.
        assert_eq!(cache.get_at(first, &1).copied(), Some(10));
        assert_eq!(cache.get_at(second, &2).copied(), Some(20));

        // The wrong key for a slot and an out-of-range slot are both misses.
        assert_eq!(cache.get_at(first, &2), None);
        assert_eq!(cache.get_at(cache.capacity(), &1), None);
        cache.check_invariants();
    }

    #[test]
    fn test_get_at_rejects_stale_evicted_slot() {
        // Evicting key 1 reuses its slot for key 3. The stale hint fails the key
        // comparison while the new key resolves at the same slot.
        let mut cache = Cache::new(NZUsize!(1));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (reused, value) = cache.get_or_insert_mut(3u64, || 0u64);
        *value = 30;

        assert_eq!(slot, reused);
        assert_eq!(cache.get_at(slot, &1), None);
        assert_eq!(cache.get_at(slot, &3).copied(), Some(30));
        cache.check_invariants();
    }

    #[test]
    fn test_get_at_rejects_freed_slot() {
        // remove keeps the slot's stale key for allocation reuse, but get_at
        // must reject a freed slot without requiring external index cleanup.
        let mut cache = Cache::new(NZUsize!(2));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        assert!(cache.remove(&1));
        assert_eq!(cache.get_at(slot, &1), None);

        // Reusing the slot for another key resolves the new key only.
        let (reused, value) = cache.get_or_insert_mut(2u64, || 0u64);
        *value = 20;
        assert_eq!(reused, slot);
        assert_eq!(cache.get_at(slot, &1), None);
        assert_eq!(cache.get_at(slot, &2).copied(), Some(20));
        cache.check_invariants();
    }

    #[test]
    fn test_get_or_insert_mut_slot_is_stable_on_hit() {
        let mut cache = Cache::new(NZUsize!(2));
        let (slot, value) = cache.get_or_insert_mut(1u64, || 0u64);
        *value = 10;
        let (hit_slot, value) = cache.get_or_insert_mut(1u64, || unreachable!());
        assert_eq!(slot, hit_slot);
        assert_eq!(*value, 10);
        cache.check_invariants();
    }

    #[test]
    fn test_get_mut_updates_resident_value() {
        let mut cache = Cache::new(NZUsize!(2));
        cache.put(1u64, 10u64);
        assert_eq!(cache.get_mut(&2), None);
        *cache.get_mut(&1).unwrap() = 11;
        assert_eq!(cache.get(&1).copied(), Some(11));
        cache.check_invariants();
    }

    #[derive(Clone, Debug)]
    enum Op {
        Get(u8),
        Peek(u8),
        Put(u8, u16),
        GetOrInsert(u8, u16),
        GetOrInsertMut(u8, u16),
        GetMut(u8, u16),
        Remove(u8),
        Retain(u8),
        Clear,
    }

    fn op_strategy(keys: u8) -> impl Strategy<Value = Op> {
        prop_oneof![
            8 => (0..keys).prop_map(Op::Get),
            8 => (0..keys).prop_map(Op::Peek),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::Put(k, v)),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsert(k, v)),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::GetOrInsertMut(k, v)),
            8 => (0..keys, any::<u16>()).prop_map(|(k, v)| Op::GetMut(k, v)),
            8 => (0..keys).prop_map(Op::Remove),
            8 => (0..keys).prop_map(Op::Retain),
            1 => Just(Op::Clear),
        ]
    }

    fn exercise_cache(capacity: usize, keys: u8, prefill: bool, ops: Vec<Op>) -> TestCaseResult {
        let mut cache = Cache::<u8, u16>::new(NonZeroUsize::new(capacity).unwrap());
        if prefill {
            cache.prefill(|| 0u16);
        }
        // Oracle: last value written for each live key. A key the cache
        // reports as present must hold its last-written value (no stale or
        // conjured values). An evicted key is simply absent.
        let mut model = HashMap::new();
        for op in ops {
            match op {
                Op::Get(key) => {
                    let value = cache.get(&key).copied();
                    prop_assert_eq!(value, cache.peek(&key).copied());
                }
                Op::Peek(key) => {
                    let _ = cache.peek(&key);
                }
                Op::Put(key, value) => {
                    cache.put(key, value);
                    model.insert(key, value);
                    prop_assert_eq!(cache.peek(&key).copied(), Some(value));
                }
                Op::GetOrInsert(key, value) => {
                    let stored = *cache.get_or_insert_with(key, || value);
                    model.insert(key, stored);
                    prop_assert_eq!(cache.peek(&key).copied(), Some(stored));
                }
                Op::GetOrInsertMut(key, value) => {
                    *cache.get_or_insert_mut(key, || value).1 = value;
                    model.insert(key, value);
                    prop_assert_eq!(cache.peek(&key).copied(), Some(value));
                }
                Op::GetMut(key, value) => {
                    if let Some(stored) = cache.get_mut(&key) {
                        *stored = value;
                        model.insert(key, value);
                    }
                }
                Op::Remove(key) => {
                    let present = cache.contains(&key);
                    prop_assert_eq!(cache.remove(&key), present);
                    model.remove(&key);
                    prop_assert!(!cache.contains(&key));
                }
                Op::Retain(key) => {
                    cache.retain(|resident, _| *resident < key);
                    model.retain(|resident, _| *resident < key);
                    prop_assert!(cache.len() <= usize::from(key).min(capacity));
                }
                Op::Clear => {
                    cache.clear();
                    model.clear();
                    prop_assert!(cache.is_empty());
                }
            }

            prop_assert!(cache.len() <= capacity);
            // The slot vector never exceeds capacity, proving reuse.
            prop_assert!(cache.slots.len() <= capacity);
            // Every present key holds its last-written value and was logically
            // inserted. Absent keys are an allowed (evicted) state.
            for key in 0..keys {
                let present = cache.contains(&key);
                prop_assert_eq!(present, cache.peek(&key).is_some());
                if present {
                    prop_assert_eq!(cache.peek(&key).copied(), model.get(&key).copied());
                }
            }
            cache.check_invariants();
        }

        Ok(())
    }

    proptest! {
        #[test]
        fn cache_invariants_hold(
            capacity in 1usize..8,
            prefill in any::<bool>(),
            ops in proptest::collection::vec(op_strategy(16), 0..256),
        ) {
            exercise_cache(capacity, 16, prefill, ops)?;
        }

        // Small needs at least two slots to exercise demotion, promotion, and
        // correlation-boundary repair.
        #[test]
        fn cache_invariants_hold_with_wide_small(
            capacity in 20usize..48,
            prefill in any::<bool>(),
            ops in proptest::collection::vec(op_strategy(64), 0..512),
        ) {
            exercise_cache(capacity, 64, prefill, ops)?;
        }
    }
    impl<K> GhostQueue<K> {
        fn check_free_slots(&self) -> HashSet<usize> {
            let mut free = HashSet::new();
            let mut current = self.free_head;
            while let Some(slot) = current {
                assert!(free.insert(slot), "duplicate Ghost free slot {slot}");
                let entry = &self.slots[slot];
                assert!(entry.key.is_none());
                assert_eq!(entry.prev, UNLINKED);
                current = linked(entry.next);
            }
            assert_eq!(self.index.len() + free.len(), self.slots.len());
            free
        }
    }

    impl<K: Hash + Eq, V> Cache<K, V> {
        /// Returns the inline replacement state for a resident slot.
        fn bits(&self, slot: Slot) -> u8 {
            self.slots[slot].state.0.load(Ordering::Relaxed)
        }

        /// Returns Small slot order from newest to oldest.
        fn small_order(&self) -> Vec<usize> {
            let mut order = Vec::with_capacity(self.small.len);
            let mut current = self.small.head;
            while let Some(slot) = current {
                order.push(slot);
                current = linked(self.topology[slot].next);
            }
            order
        }

        /// Returns Main slot order starting at the CLOCK hand.
        fn main_order(&self) -> Vec<usize> {
            let mut order = Vec::with_capacity(self.main.len);
            let Some(hand) = self.main.hand else {
                return order;
            };
            let mut current = hand;
            loop {
                order.push(current);
                current = self.topology[current].next;
                assert_ne!(current, UNLINKED);
                if current == hand {
                    return order;
                }
            }
        }

        /// Returns Ghost slot order from newest to oldest.
        fn ghost_order(&self) -> Vec<usize> {
            let mut order = Vec::with_capacity(self.ghost.index.len());
            let mut current = self.ghost.head;
            while let Some(slot) = current {
                order.push(slot);
                current = linked(self.ghost.slots[slot].next);
            }
            order
        }

        /// Returns Small keys from newest to oldest.
        fn small_keys(&self) -> Vec<K>
        where
            K: Clone,
        {
            self.small_order()
                .into_iter()
                .map(|slot| self.slots[slot].key.clone())
                .collect()
        }

        /// Returns Main keys starting at the CLOCK hand.
        fn main_keys(&self) -> Vec<K>
        where
            K: Clone,
        {
            self.main_order()
                .into_iter()
                .map(|slot| self.slots[slot].key.clone())
                .collect()
        }

        /// Returns Ghost keys from newest to oldest.
        fn ghost_keys(&self) -> Vec<K>
        where
            K: Clone,
        {
            self.ghost_order()
                .into_iter()
                .map(|slot| {
                    self.ghost.slots[slot]
                        .key
                        .as_ref()
                        .expect("live Ghost entry must have a key")
                        .clone()
                })
                .collect()
        }

        /// Asserts resident ownership, queue topology, and exact history agree.
        fn check_invariants(&self) {
            assert!(self.slots.len() <= self.capacity);
            assert_eq!(self.topology.len(), self.capacity);
            assert!(self.small.len <= self.small.capacity);
            assert!(self.main.len <= self.main.capacity);
            assert_eq!(self.index.len(), (self.small.len + self.main.len));
            assert_eq!(self.index.len() + self.free.len(), self.slots.len());

            let free: HashSet<_> = self.free.iter().copied().collect();
            assert_eq!(free.len(), self.free.len(), "duplicate resident free slot");
            let small = self.small_order();
            let main = self.main_order();
            assert_eq!(small.len(), self.small.len);
            assert_eq!(main.len(), self.main.len);
            let young_len = self
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
            assert!(self.small.admissions <= ADMISSION_GENERATION_MASK);
            assert!(young_len <= self.small.correlation_window);
            assert!(young_len <= self.small.len);

            let mut resident = HashSet::new();
            for (rank, &slot) in small.iter().enumerate() {
                assert!(resident.insert(slot), "duplicate Small resident {slot}");
                assert!(self.slots[slot].live);
                assert_eq!(self.topology[slot].location(), Location::Small);
                let state = self.bits(slot);
                let young = rank < young_len;
                assert_eq!(state & CORRELATED != 0, young);
                if young {
                    assert_eq!(state, CORRELATED);
                    let age = self
                        .small
                        .admissions
                        .wrapping_sub(self.topology[slot].admitted_at())
                        & ADMISSION_GENERATION_MASK;
                    assert!(age < self.small.correlation_window);
                } else {
                    assert_eq!(self.topology[slot].admitted_at(), 0);
                }
                let expected_prev = rank.checked_sub(1).map(|rank| small[rank]);
                let expected_next = small.get(rank + 1).copied();
                assert_eq!(linked(self.topology[slot].prev), expected_prev);
                assert_eq!(linked(self.topology[slot].next), expected_next);
            }
            assert_eq!(self.small.head, small.first().copied());
            assert_eq!(self.small.tail, small.last().copied());
            let expected_young_tail = young_len
                .checked_sub(1)
                .and_then(|rank| small.get(rank))
                .copied();
            assert_eq!(self.small.young_tail, expected_young_tail);

            for (rank, &slot) in main.iter().enumerate() {
                assert!(resident.insert(slot), "resident {slot} in two queues");
                assert!(self.slots[slot].live);
                assert_eq!(self.topology[slot].location(), Location::Main);
                assert_eq!(self.topology[slot].admitted_at(), 0);
                assert_eq!(self.bits(slot) & CORRELATED, 0);
                assert_eq!(
                    self.topology[slot].prev,
                    main[(rank + main.len() - 1) % main.len()]
                );
                assert_eq!(self.topology[slot].next, main[(rank + 1) % main.len()]);
            }

            let indexed: HashSet<_> = self.index.iter().copied().collect();
            assert_eq!(indexed.len(), self.index.len(), "duplicate indexed slot");
            assert_eq!(indexed, resident);
            for &slot in &self.index {
                assert!(slot < self.slots.len());
                assert!(resident.contains(&slot));
                assert_eq!(self.find_slot(&self.slots[slot].key), Some(slot));
            }
            for slot in 0..self.slots.len() {
                if resident.contains(&slot) {
                    assert!(!free.contains(&slot));
                } else {
                    assert!(free.contains(&slot));
                    assert!(!self.slots[slot].live);
                    assert_eq!(self.topology[slot].location(), Location::Free);
                    assert_eq!(self.topology[slot].admitted_at(), 0);
                }
            }
            for slot in self.slots.len()..self.topology.len() {
                assert_eq!(self.topology[slot].location(), Location::Free);
                assert_eq!(self.topology[slot].admitted_at(), 0);
            }

            assert!(self.ghost.index.len() <= self.ghost.capacity);
            assert!(self.ghost.slots.len() <= self.ghost.capacity);
            let ghost = self.ghost_order();
            assert_eq!(ghost.len(), self.ghost.index.len());
            let ghost_free = self.ghost.check_free_slots();
            let mut seen_ghost = HashSet::new();
            for (rank, &slot) in ghost.iter().enumerate() {
                assert!(seen_ghost.insert(slot));
                assert!(!ghost_free.contains(&slot));
                let key = self.ghost.slots[slot]
                    .key
                    .as_ref()
                    .expect("linked Ghost entry must have a key");
                assert_eq!(
                    self.ghost
                        .index
                        .find(self.hasher.hash_one(key), |candidate| {
                            self.ghost.slots[*candidate].key.as_ref() == Some(key)
                        }),
                    Some(&slot),
                );
                assert!(!self.contains(key));
                let expected_prev = rank.checked_sub(1).map(|rank| ghost[rank]);
                let expected_next = ghost.get(rank + 1).copied();
                assert_eq!(linked(self.ghost.slots[slot].prev), expected_prev);
                assert_eq!(linked(self.ghost.slots[slot].next), expected_next);
            }
            assert_eq!(self.ghost.head, ghost.first().copied());
            assert_eq!(self.ghost.tail, ghost.last().copied());
            for (slot, entry) in self.ghost.slots.iter().enumerate() {
                if seen_ghost.contains(&slot) {
                    assert!(entry.key.is_some());
                } else {
                    assert!(ghost_free.contains(&slot));
                    assert!(entry.key.is_none());
                }
            }
        }
    }

    #[test]
    fn test_resident_metadata_fits_three_words_and_preserves_links() {
        assert_eq!(
            core::mem::size_of::<ResidentSlot>(),
            3 * core::mem::size_of::<usize>()
        );

        let mut slot = ResidentSlot {
            prev: usize::MAX - 1,
            next: usize::MAX - 2,
            location_and_admission: Location::Small.pack(ADMISSION_GENERATION_MASK),
        };
        assert_eq!(slot.location(), Location::Small);
        assert_eq!(slot.admitted_at(), ADMISSION_GENERATION_MASK);
        assert_eq!(slot.prev, usize::MAX - 1);
        assert_eq!(slot.next, usize::MAX - 2);

        slot.location_and_admission = Location::Main.pack(0);
        assert_eq!(slot.location(), Location::Main);
        assert_eq!(slot.admitted_at(), 0);
        assert_eq!(slot.prev, usize::MAX - 1);
        assert_eq!(slot.next, usize::MAX - 2);

        slot.location_and_admission = Location::Free.pack(0);
        assert_eq!(slot.location(), Location::Free);
        assert_eq!(slot.admitted_at(), 0);
    }

    #[test]
    fn test_partitions_round_for_tiny_capacities() {
        // Ratio-derived partitions round down and the correlation window rounds
        // up. Capacities above one still keep at least one Small slot, while
        // capacity one uses Main alone.
        let expected = [
            (1, 0, 1, 0, 0),
            (2, 1, 1, 1, 1),
            (10, 1, 9, 1, 5),
            (11, 1, 10, 1, 5),
            (20, 2, 18, 1, 10),
            (40, 4, 36, 2, 20),
        ];
        for (capacity, small, main, window, ghost) in expected {
            let cache = Cache::<u64, u64>::new(NonZeroUsize::new(capacity).unwrap());
            assert_eq!(cache.small.capacity, small);
            assert_eq!(cache.main.capacity, main);
            assert_eq!(cache.small.correlation_window, window);
            assert_eq!(cache.ghost.capacity, ghost);
            cache.check_invariants();
        }

        // Exercise every tiny partition through repeated replacement, where
        // off-by-one errors in the queue bounds are easiest to expose.
        for capacity in 1..=20 {
            let mut cache = Cache::new(NonZeroUsize::new(capacity).unwrap());
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
        let mut cache = Cache::new(NZUsize!(1));
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
        let mut cache = Cache::new(NZUsize!(20));
        for key in 0..20u64 {
            cache.put(key, key);
        }

        assert_eq!(cache.small_keys(), vec![1, 0]);
        assert_eq!(cache.main_keys(), (2..20).collect::<Vec<_>>());
        for key in 2..20u64 {
            let slot = cache.find_slot(&key).unwrap();
            assert_eq!(cache.bits(slot) & REFERENCED, 0);
        }
        cache.check_invariants();
    }

    #[test]
    fn test_empty_residents_preserve_precise_ghost_history() {
        // Resident filtering does not erase unrelated Ghost evidence. The
        // cache may therefore retain useful history with no live residents.
        let mut cache = Cache::new(NZUsize!(2));
        for key in 1..=3u64 {
            cache.put(key, key);
        }
        assert_eq!(cache.ghost_keys(), vec![1]);

        cache.retain(|key, _| *key == 1);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.ghost_keys(), vec![1]);
        assert!(!cache.ghost.index.is_empty());

        cache.retain(|_, _| false);
        assert_eq!(cache.small.len + cache.main.len, 0);
        assert_eq!(cache.ghost_keys(), vec![1]);
        cache.check_invariants();
    }

    #[test]
    fn test_correlation_window_ignores_only_young_hits() {
        // Key 4 is at the Small head, inside the two-entry correlation window.
        // Its hit must not set the bit, so a scan ages and evicts it to Ghost.
        let mut correlated = Cache::new(NZUsize!(40));
        for key in 1..=40u64 {
            correlated.put(key, key);
        }
        assert_eq!(correlated.small_keys(), vec![4, 3, 2, 1]);
        assert_eq!(correlated.get(&4), Some(&4));
        let slot = correlated.find_slot(&4).unwrap();
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
        let mut reused = Cache::new(NZUsize!(40));
        for key in 1..=40u64 {
            reused.put(key, key);
        }
        assert_eq!(reused.get(&1), Some(&1));
        reused.put(41, 41);
        assert!(reused.small_keys().contains(&41));
        assert!(reused.main_keys().contains(&1));
        let slot = reused.find_slot(&1).unwrap();
        assert_eq!(reused.bits(slot) & REFERENCED, 0);
        assert!(reused.ghost_keys().is_empty());
        reused.check_invariants();
    }

    #[test]
    fn test_removing_younger_entry_does_not_rewind_correlation_age() {
        let mut cache = Cache::new(NZUsize!(20));
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
        let mut cache = Cache::new(NZUsize!(40));
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
        let mut cache = Cache::new(NZUsize!(20));
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
        let mut cache = Cache::new(NZUsize!(2));
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
        cache.check_invariants();
    }

    #[test]
    fn test_promoting_small_replaces_from_full_main() {
        // Reference the original Small tail so the next cold miss promotes it
        // while keeping both fixed-size resident partitions full.
        let mut cache = Cache::new(NZUsize!(20));
        for key in 0..20u64 {
            cache.put(key, key);
        }
        for key in 0..18u64 {
            assert_eq!(cache.get(&key), Some(&key));
        }
        cache.put(20, 20);
        assert_eq!(cache.main.len, cache.main.capacity);
        assert_eq!(cache.small.len, 2);
        let slot = cache.find_slot(&0).unwrap();
        assert_eq!(cache.bits(slot) & REFERENCED, 0);

        // The sweep evicted key 18 and left the hand on key 19. The promoted
        // key links immediately before the hand, so it is swept last.
        assert_eq!(
            cache.main_keys(),
            core::iter::once(19)
                .chain(2..=17)
                .chain(core::iter::once(0))
                .collect::<Vec<_>>()
        );

        // Repeat the transition with a full Main CLOCK. The promoted key keeps
        // its slot and starts in Main with a clear reference bit.
        let promoted = *cache.small_keys().last().unwrap();
        assert_eq!(promoted, 1);
        assert_eq!(cache.get(&promoted), Some(&promoted));
        cache.put(21, 21);

        // Key 19 was unreferenced at the hand, so it is evicted and the hand
        // moves to key 2. Key 1 links before the hand, after key 0.
        assert_eq!(
            cache.main_keys(),
            (2..=17).chain([0, 1]).collect::<Vec<_>>()
        );
        let slot = cache.find_slot(&promoted).unwrap();
        assert_eq!(cache.bits(slot) & REFERENCED, 0);
        assert!(cache.small_keys().contains(&21));
        assert_eq!(cache.main.len, cache.main.capacity);
        assert_eq!(cache.small.len, 2);
        cache.check_invariants();
    }

    #[test]
    fn test_slot_stays_stable_on_promotion_and_goes_stale_on_reuse() {
        // Promotion changes only resident topology, so key 1 keeps its original
        // slot and the existing lookup hint remains valid.
        let mut cache = Cache::new(NZUsize!(40));
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
        let slot42 = cache.find_slot(&42).unwrap();
        assert_eq!(slot42, slot2);
        assert_eq!(cache.get_at(slot2, &2), None);
        assert_eq!(cache.get_at(slot42, &42), Some(&420));
        cache.check_invariants();
    }

    #[test]
    fn test_scan_does_not_displace_main() {
        // Warm-up places keys 1 through 9 in Main. A one-cache-capacity scan is
        // absorbed by Small and leaves that Main working set intact.
        let mut cache = Cache::new(NZUsize!(10));
        for key in 0..10u64 {
            cache.put(key, key);
        }
        let mut protected = 1..10u64;
        assert_eq!(cache.main.len, 9);

        for key in 100..110u64 {
            cache.put(key, key);
        }
        assert!(protected.all(|key| cache.peek(&key).is_some()));
        cache.check_invariants();
    }

    #[test]
    fn test_prefill_reuses_values_through_churn() {
        // Prefill allocates every value once. Replacement churn must keep reusing
        // those same stable slots without invoking the factory again.
        let mut makes = 0usize;
        let mut cache = Cache::<u64, Vec<u8>>::new(NZUsize!(20));
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
        let mut cache = Cache::new(NZUsize!(20));
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
        assert!(
            cache
                .index
                .iter()
                .all(|&slot| cache.slots[slot].key % 2 == 0)
        );
        cache.check_invariants();

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.small.len + cache.main.len, 0);
        assert!(cache.ghost.index.is_empty());
        assert!(cache.ghost_keys().is_empty());
        cache.check_invariants();
    }

    #[test]
    fn test_shared_hits_are_concurrent() {
        // Shared lookups race only on the relaxed per-slot reference bit. The
        // accumulated hit must still protect key 1 on the next insertion.
        let mut cache = Cache::new(NZUsize!(40));
        for key in 1..=40u64 {
            cache.put(key, key);
        }
        let slot = cache.find_slot(&1).unwrap();
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
    fn test_fallible_factory_error_leaves_cache_unchanged() {
        // Key 1 is in Ghost. A failed factory must return before cache
        // insertion consumes that evidence or changes resident topology.
        let mut cache = Cache::new(NZUsize!(2));
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

    #[test]
    fn test_correlation_age_survives_admission_counter_wrap() {
        // Correlation ages are modular differences, so the packed generation can
        // wrap inside the window and leave the same Small state as a fresh run.
        let mut wrapped = Cache::new(NZUsize!(40));
        wrapped.small.admissions = ADMISSION_GENERATION_MASK - 1;
        let mut plain = Cache::new(NZUsize!(40));
        for key in 1..=40u64 {
            wrapped.put(key, key);
            plain.put(key, key);
        }
        assert_eq!(wrapped.small_keys(), plain.small_keys());
        for key in wrapped.small_keys() {
            assert_eq!(
                wrapped.bits(wrapped.find_slot(&key).unwrap()),
                plain.bits(plain.find_slot(&key).unwrap())
            );
        }

        // Key 1 left the window across the first wrap. Repeatedly remove both
        // young residents and cross the wrap with replacements. The older
        // survivor remains eligible because young_tail, not generation
        // equality, owns youth.
        assert_eq!(wrapped.get(&1), Some(&1));
        wrapped.retain(|key, _| *key != 4);
        assert!(wrapped.remove(&3));
        assert_eq!(wrapped.small.young_tail, None);

        for cycle in 0..8u64 {
            let first = 41 + 2 * cycle;
            let second = first + 1;
            wrapped.small.admissions = ADMISSION_GENERATION_MASK - 1;
            wrapped.put(first, first);
            let expected_young_tail = wrapped.find_slot(&first);
            wrapped.put(second, second);
            assert_eq!(wrapped.small.young_tail, expected_young_tail);
            wrapped.check_invariants();

            if cycle < 7 {
                wrapped.retain(|key, _| *key != second);
                assert!(wrapped.remove(&first));
                assert_eq!(wrapped.small.young_tail, None);
            }
        }

        wrapped.put(57, 57);
        assert!(wrapped.main_keys().contains(&1));
        wrapped.check_invariants();

        wrapped.clear();
        assert_eq!(wrapped.small.admissions, 0);
        wrapped.check_invariants();
    }

    #[derive(Debug, PartialEq, Eq)]
    struct GhostKey {
        value: u64,
        owner: Rc<()>,
    }

    impl Hash for GhostKey {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            state.write_u8(0);
        }
    }

    fn exercise_colliding_ghost(capacity: usize, reserve: bool) {
        let owner = Rc::new(());
        let hasher = Hasher::with_seeds(1, 2, 3, 4);
        let key = |value| GhostKey {
            value,
            owner: Rc::clone(&owner),
        };
        let mut ghost = GhostQueue::new(capacity);
        if !reserve {
            // Exercise the insertion callback through multiple table growths.
            ghost.index = HashTable::new();
        }
        let mut expected = VecDeque::new();
        for step in 0..2048u64 {
            let value = (step * 17 + step / 5) % 127;
            {
                let position = expected.iter().position(|entry| *entry == value);
                let requested = key(value);
                let requested_hash = hasher.hash_one(&requested);
                assert_eq!(
                    ghost.discard(&requested, requested_hash),
                    position.is_some()
                );
                if let Some(position) = position {
                    expected.remove(position);
                }
                if step % 5 != 0 {
                    let historical = key(value);
                    let historical_hash = hasher.hash_one(&historical);
                    ghost.push(historical, historical_hash, &hasher);
                    if capacity != 0 {
                        expected.push_front(value);
                        expected.truncate(capacity);
                    }
                }
            }
            if step == 777 || step == 1333 {
                ghost.clear();
                expected.clear();
            }

            let mut actual = Vec::new();
            let mut linked_slots = HashSet::new();
            let mut previous = None;
            let mut current = ghost.head;
            while let Some(slot) = current {
                assert!(linked_slots.insert(slot));
                let entry = &ghost.slots[slot];
                assert_eq!(linked(entry.prev), previous);
                actual.push(entry.key.as_ref().unwrap().value);
                previous = current;
                current = linked(entry.next);
            }
            assert_eq!(ghost.tail, previous);
            assert_eq!(actual, expected.iter().copied().collect::<Vec<_>>());
            assert_eq!(
                ghost.index.iter().copied().collect::<HashSet<_>>(),
                linked_slots
            );
            assert_eq!(ghost.index.len(), expected.len());
            assert!(ghost.slots.len() <= capacity);
            let free = ghost.check_free_slots();
            for (slot, entry) in ghost.slots.iter().enumerate() {
                assert_eq!(entry.key.is_some(), linked_slots.contains(&slot));
                assert_eq!(free.contains(&slot), entry.key.is_none());
            }

            // GhostKey is not Clone, and each live historical key owns one Rc.
            assert_eq!(Rc::strong_count(&owner), expected.len() + 1);
        }
        drop(ghost);
        assert_eq!(Rc::strong_count(&owner), 1);
    }

    #[test]
    fn test_ghost_collision_churn_and_key_ownership() {
        for capacity in [0, 1, 2, 31] {
            exercise_colliding_ghost(capacity, true);
        }
    }

    #[test]
    fn test_ghost_rehash_reads_live_keys() {
        exercise_colliding_ghost(31, false);
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CollidingKey(u64);

    impl Hash for CollidingKey {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            state.write_u8(0);
        }
    }

    #[test]
    fn test_shared_hasher_drives_resident_and_ghost_rehashes() {
        let mut cache = Cache::new(NZUsize!(20));

        // Removing both reservations forces both indexes to call their rehash
        // callbacks while the public Cache API drives all replacement transitions.
        cache.index = HashTable::new();
        cache.ghost.index = HashTable::new();
        cache.hasher = Hasher::with_seeds(1, 2, 3, 4);

        let mut resident_grew = false;
        let mut ghost_grew = false;
        for key in 0..256 {
            let resident_capacity = cache.index.capacity();
            let ghost_capacity = cache.ghost.index.capacity();
            cache.put(CollidingKey(key), key);
            resident_grew |= cache.index.capacity() > resident_capacity;
            ghost_grew |= cache.ghost.index.capacity() > ghost_capacity;
            cache.check_invariants();
        }
        assert!(resident_grew, "resident index must rehash");
        assert!(ghost_grew, "Ghost index must rehash");

        let ghost = cache.ghost_keys();
        assert_eq!(ghost.len(), cache.ghost.capacity);
        assert_eq!(ghost.iter().collect::<HashSet<_>>().len(), ghost.len());
        assert!(ghost.iter().all(|key| !cache.contains(key)));

        // Constant hashes still consume only the exact requested history key.
        let requested = ghost[ghost.len() / 2].clone();
        cache.put(requested.clone(), u64::MAX);
        assert_eq!(cache.get(&requested), Some(&u64::MAX));
        assert!(!cache.ghost_keys().contains(&requested));
        cache.check_invariants();
    }

    #[test]
    fn test_borrowed_keys_keep_independent_ghost_history() {
        let names = [
            String::from("first"),
            String::from("second"),
            String::from("third"),
        ];
        let mut cache = Cache::new(NZUsize!(2));
        for (value, name) in names.iter().enumerate() {
            cache.put(vec![name.as_str()], value);
        }
        assert_eq!(cache.ghost_keys(), vec![vec![names[0].as_str()]]);
        assert!(!cache.remove(&vec![names[0].as_str()]));
        assert!(cache.ghost_keys().is_empty());
        assert_eq!(cache.get(&vec![names[2].as_str()]), Some(&2));
        cache.check_invariants();
    }

    #[test]
    fn test_main_sweep_reaches_unreferenced_resident_beyond_128() {
        let mut cache = Cache::new(NZUsize!(200));
        for key in 0..200u64 {
            cache.put(key, key);
        }
        for key in 20..149 {
            assert_eq!(cache.get(&key), Some(&key));
        }
        cache.put(200, 200);
        assert_eq!(cache.ghost_keys(), vec![0]);
        cache.put(0, 0);
        assert_eq!(cache.peek(&149), None);
        for key in 20..149 {
            assert_eq!(cache.peek(&key), Some(&key));
            assert_eq!(cache.bits(cache.find_slot(&key).unwrap()), 0);
        }
        cache.check_invariants();
    }

    #[derive(Clone)]
    struct CountingKey {
        id: usize,
        hashes: Rc<Cell<usize>>,
    }

    impl CountingKey {
        fn new(id: usize) -> Self {
            Self {
                id,
                hashes: Rc::new(Cell::new(0)),
            }
        }

        fn hashes(&self) -> usize {
            self.hashes.get()
        }
    }

    impl PartialEq for CountingKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for CountingKey {}

    impl Hash for CountingKey {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.hashes.set(self.hashes.get() + 1);
            self.id.hash(state);
        }
    }

    #[test]
    fn shared_hashes_without_rehash_steps() {
        let one = CountingKey::new(1);
        let two = CountingKey::new(2);
        let three = CountingKey::new(3);
        let mut cache = Cache::<CountingKey, usize>::new(NonZeroUsize::new(2).unwrap());

        // The reserved resident and Ghost tables cannot rehash during this short
        // sequence, so every count belongs to the key's explicit operation path.
        cache.put(one.clone(), 1);
        cache.put(two.clone(), 2);
        assert_eq!(one.hashes(), 1);
        assert_eq!(two.hashes(), 1);

        // Key 3 replaces Small's key 1. Each incoming key and the transferred
        // victim is hashed once across its resident and Ghost operations.
        cache.put(three.clone(), 3);
        assert_eq!(one.hashes(), 2);
        assert_eq!(two.hashes(), 1);
        assert_eq!(three.hashes(), 1);

        // A nonresident removal shares the resident-miss hash with Ghost discard.
        assert!(!cache.remove(&one));
        assert_eq!(one.hashes(), 3);

        // Resident retain and clear operate from canonical table/slot ownership
        // and do not need a new key hash.
        cache.retain(|key, _| key.id != 3);
        assert_eq!(three.hashes(), 1);
        cache.clear();
        assert_eq!(two.hashes(), 1);
        assert_eq!(three.hashes(), 1);
    }

    #[derive(Clone, Default, Eq, PartialEq)]
    struct ProbeKey<const COLLIDE: bool>(String);
    impl<const COLLIDE: bool> Hash for ProbeKey<COLLIDE> {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            if COLLIDE {
                0u8.hash(state);
            } else {
                self.0.hash(state);
            }
        }
    }

    fn exercise_rehash<const COLLIDE: bool>() {
        for capacity in [1, 2, 31, 64] {
            for prefill in [false, true] {
                let mut cache =
                    Cache::<ProbeKey<COLLIDE>, Vec<u8>>::new(NonZeroUsize::new(capacity).unwrap());

                // Zero reserve forces actual rehash callbacks during lazy growth and
                // publication into prefilled storage, even with constant hashes.
                cache.index = HashTable::new();
                cache.hasher = super::Hasher::with_seeds(1, 2, 3, 4);
                if prefill {
                    cache.prefill(Vec::new);
                }
                let mut hints = Vec::new();
                let mut live = HashMap::new();
                let mut grew = false;
                for step in 0..1024usize {
                    let key = ProbeKey::<COLLIDE>(format!("key-{step}"));
                    let before = cache.index.capacity();
                    let (slot, value) = cache.get_or_insert_mut(key.clone(), Vec::new);
                    value.clear();
                    value.extend_from_slice(&step.to_le_bytes());
                    let value_address = value as *const Vec<u8>;
                    grew |= cache.index.capacity() > before;
                    live.retain(|old_key, old: &mut (usize, *const Vec<u8>)| {
                        if old.0 == slot {
                            assert!(cache.get_at(old.0, old_key).is_none());
                            false
                        } else {
                            true
                        }
                    });
                    live.insert(key.clone(), (slot, value_address));
                    hints.push((slot, key));
                    if step % 11 == 5 {
                        let removed =
                            ProbeKey::<COLLIDE>(format!("key-{}", step.saturating_sub(1)));
                        assert_eq!(cache.remove(&removed), live.remove(&removed).is_some());
                    }
                    if step % 37 == 9 {
                        cache.retain(|key, _| key.0.as_bytes().last().unwrap() % 2 == 0);
                        live.retain(|key, _| key.0.as_bytes().last().unwrap() % 2 == 0);
                    }
                    if step % 127 == 100 {
                        cache.clear();
                        live.clear();
                        if prefill {
                            cache.prefill(Vec::new);
                        }
                    }
                    assert_eq!(cache.len(), live.len());
                    cache.check_invariants();
                    for (key, &(slot, address)) in &live {
                        let value = cache.peek(key).unwrap();
                        let expected = key.0[4..].parse::<usize>().unwrap();
                        assert_eq!(value.as_slice(), expected.to_le_bytes());
                        assert_eq!(value as *const Vec<u8>, address);
                        assert_eq!(cache.get_at(slot, key), Some(value));
                    }
                    for (slot, key) in &hints {
                        let expected = live.get(key).filter(|entry| entry.0 == *slot);
                        assert_eq!(cache.get_at(*slot, key).is_some(), expected.is_some());
                    }
                    assert!(
                        cache
                            .get_at(usize::MAX, &ProbeKey::<COLLIDE>::default())
                            .is_none()
                    );
                }
                assert!(grew, "the test must exercise index growth");
            }
        }
    }

    #[test]
    fn collisions_rehash_and_stable_values() {
        exercise_rehash::<true>();
    }

    #[derive(Default)]
    struct Counts {
        owners: RefCell<HashMap<usize, usize>>,
        clones: RefCell<Vec<usize>>,
        values: Cell<usize>,
    }
    struct OwnedKey {
        id: usize,
        counts: Rc<Counts>,
    }
    impl OwnedKey {
        fn new(id: usize, counts: &Rc<Counts>) -> Self {
            *counts.owners.borrow_mut().entry(id).or_default() += 1;
            Self {
                id,
                counts: Rc::clone(counts),
            }
        }
    }
    impl Clone for OwnedKey {
        fn clone(&self) -> Self {
            self.counts.clones.borrow_mut().push(self.id);
            Self::new(self.id, &self.counts)
        }
    }
    impl PartialEq for OwnedKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }
    impl Eq for OwnedKey {}
    impl Hash for OwnedKey {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            0u8.hash(state);
        }
    }
    impl Drop for OwnedKey {
        fn drop(&mut self) {
            *self.counts.owners.borrow_mut().get_mut(&self.id).unwrap() -= 1;
        }
    }
    struct OwnedValue(Rc<Counts>);
    impl Drop for OwnedValue {
        fn drop(&mut self) {
            self.0.values.set(self.0.values.get() + 1);
        }
    }

    #[test]
    fn eviction_does_not_clone_keys() {
        let counts = Rc::new(Counts::default());
        let mut cache = Cache::<OwnedKey, OwnedValue>::new(NonZeroUsize::new(2).unwrap());
        for id in 0..8 {
            cache.put(OwnedKey::new(id, &counts), OwnedValue(Rc::clone(&counts)));
        }
        assert!(counts.clones.borrow().is_empty());
        assert_eq!(counts.values.get(), 6);
        drop(cache);
        assert!(counts.owners.borrow().values().all(|&n| n == 0));
        assert_eq!(counts.values.get(), 8);
    }

    #[test]
    fn canonical_key_move_and_ghost_drop_ownership() {
        let counts = Rc::new(Counts::default());
        let mut cache = Cache::<OwnedKey, OwnedValue>::new(NonZeroUsize::new(2).unwrap());
        for id in 0..2 {
            cache.put(OwnedKey::new(id, &counts), OwnedValue(Rc::clone(&counts)));
        }
        assert!(
            counts.clones.borrow().is_empty(),
            "vacant insertion owns the incoming key directly"
        );
        assert!(counts.owners.borrow().values().all(|&n| n == 1));
        cache.get_or_insert_mut(OwnedKey::new(2, &counts), || {
            panic!("eviction must reuse V")
        });
        assert!(counts.clones.borrow().is_empty());
        assert_eq!(
            *counts.owners.borrow(),
            HashMap::from([(0, 1), (1, 1), (2, 1)])
        );

        // Key 0 is historical: its admission must consume Ghost and evict Main's 1.
        cache.get_or_insert_mut(OwnedKey::new(0, &counts), || {
            panic!("Ghost hit must reuse V")
        });
        assert!(counts.clones.borrow().is_empty());
        assert_eq!(
            *counts.owners.borrow(),
            HashMap::from([(0, 1), (1, 0), (2, 1)])
        );
        assert!(cache.remove(&OwnedKey::new(2, &counts)));
        assert_eq!(
            counts.owners.borrow()[&2],
            1,
            "free slots retain their stale key"
        );
        cache.get_or_insert_mut(OwnedKey::new(3, &counts), || {
            panic!("free slot must reuse V")
        });
        assert!(
            counts.clones.borrow().is_empty(),
            "free reuse must not clone keys"
        );
        assert_eq!(counts.owners.borrow()[&2], 0);
        assert_eq!(counts.values.get(), 0);
        cache.retain(|_, _| false);
        assert!(cache.is_empty());
        assert_eq!(counts.values.get(), 0);
        cache.clear();
        assert!(counts.owners.borrow().values().all(|&n| n == 0));
        assert_eq!(counts.values.get(), 2);
        cache.put(OwnedKey::new(4, &counts), OwnedValue(Rc::clone(&counts)));
        drop(cache);
        assert!(counts.owners.borrow().values().all(|&n| n == 0));
        assert_eq!(counts.values.get(), 3);
    }

    #[test]
    fn distinct_hashes_rehash_and_stable_values() {
        exercise_rehash::<false>();
    }

    // Equality ignores metadata so an incoming key can differ from Ghost's owner.
    #[derive(Debug)]
    struct NonCloneKey {
        id: usize,
        metadata: usize,
    }
    impl PartialEq for NonCloneKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }
    impl Eq for NonCloneKey {}
    impl Hash for NonCloneKey {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            0u8.hash(state);
        }
    }

    #[test]
    fn non_clone_keys_keep_incoming_metadata_on_ghost_hits() {
        let mut cache = Cache::new(NonZeroUsize::new(2).unwrap());
        let key = |id, metadata| NonCloneKey { id, metadata };
        let (original_slot, _) = cache.get_or_insert_mut(key(0, 10), || 0);
        cache.put(key(1, 11), 1);
        cache.put(key(2, 12), 2);
        assert_eq!(cache.get_at(original_slot, &key(0, 0)), None);
        cache.check_invariants();

        // The historical key is consumed while the caller's key becomes canonical.
        let (slot, value) = cache.get_or_insert_mut(key(0, 20), || unreachable!());
        *value = 20;
        assert_eq!(cache.get_at(slot, &key(0, 0)), Some(&20));
        cache.retain(|key, value| {
            if key.id == 0 {
                assert_eq!(key.metadata, 20);
                assert_eq!(*value, 20);
            }
            true
        });
        cache.check_invariants();

        assert!(cache.remove(&key(0, 0)));
        assert_eq!(cache.get_at(slot, &key(0, 0)), None);
        let (reused, value) = cache.get_or_insert_mut(key(3, 30), || unreachable!());
        assert_eq!(reused, slot);
        assert_eq!(*value, 20);
        cache.check_invariants();
        cache.clear();
        cache.check_invariants();
    }

    struct PanickingKey {
        id: usize,
        panic_on: Rc<Cell<Option<usize>>>,
    }
    impl PartialEq for PanickingKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }
    impl Eq for PanickingKey {}
    impl Hash for PanickingKey {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }
    impl Drop for PanickingKey {
        fn drop(&mut self) {
            if self.panic_on.get() == Some(self.id) {
                self.panic_on.set(None);
                panic!("key destructor panic");
            }
        }
    }

    #[test]
    fn displaced_key_destructors_follow_replacement_bookkeeping() {
        let panic_on = Rc::new(Cell::new(None));
        let key = |id| PanickingKey {
            id,
            panic_on: Rc::clone(&panic_on),
        };
        let mut cache = Cache::new(NonZeroUsize::new(2).unwrap());
        for id in 0..3 {
            cache.put(key(id), id);
        }

        // A full Ghost replaces its oldest history before dropping that old key.
        panic_on.set(Some(0));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.put(key(3), 3)));
        assert!(result.is_err());
        assert_eq!(cache.peek(&key(3)), Some(&3));
        cache.check_invariants();

        // Discard returns the historical slot to its free list before dropping.
        panic_on.set(Some(2));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.remove(&key(2))));
        assert!(result.is_err());
        cache.check_invariants();
        cache.put(key(4), 4);
        cache.check_invariants();

        // A Ghost hit replaces Main's canonical key with the caller's owned key.
        panic_on.set(Some(1));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.put(key(3), 30)));
        assert!(result.is_err());
        assert_eq!(cache.peek(&key(3)), Some(&30));
        cache.check_invariants();

        // A freed resident retains its stale key until the next published admission.
        assert!(cache.remove(&key(4)));
        panic_on.set(Some(4));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.put(key(5), 5)));
        assert!(result.is_err());
        assert_eq!(cache.peek(&key(5)), Some(&5));
        cache.check_invariants();
    }
}
