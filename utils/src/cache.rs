//! A fixed-capacity key-value cache using Clock2Q+ replacement.
//!
//! Clock2Q+ separates residents into a Small probation queue and a Main CLOCK
//! ring. New entries enter Small, where hits outside a correlation window earn
//! promotion to Main. Main gives referenced entries a second chance before
//! eviction. A bounded Ghost queue records keys evicted from Small; a later
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
//!
//! # References
//!
//! - [Clock2Q+: A Simple and Efficient Replacement Algorithm for Metadata
//!   Cache in VMware vSAN](https://arxiv.org/abs/2511.21958)

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::{
    hash::Hash,
    num::NonZeroUsize,
    sync::atomic::{AtomicU8, Ordering},
};
use hashbrown::HashTable;

type Hasher = ahash::RandomState;

/// Stable identifier for cache storage.
pub type Slot = usize;

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
    /// Resident membership; each indexed slot owns its canonical key.
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
    pub fn get_at(&self, slot: Slot, key: &K) -> Option<&V> {
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
    ///
    /// # Panics
    ///
    /// If `make` panics while producing a value for a new slot, replacement metadata
    /// may already have been updated. If the panic is caught, this cache must
    /// not be used again.
    pub fn get_or_insert_mut<F: FnOnce() -> V>(&mut self, key: K, make: F) -> (Slot, &mut V) {
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

    /// Conditionally removes a resident `key`.
    ///
    /// Returns `None` when `key` is not resident. The predicate is not called
    /// and nonresident history is preserved. For a resident, the
    /// predicate is called exactly once with its value. A rejected resident
    /// records use and returns `Some(false)`, while an accepted resident is
    /// removed without first recording use and returns `Some(true)`.
    ///
    /// The removed slot and its allocation are retained for reuse, so the
    /// value is not returned.
    ///
    /// # Panics
    ///
    /// If `predicate` panics, this operation makes no structural or replacement
    /// mutation before unwinding.
    #[inline]
    pub fn remove_if<F: FnOnce(&V) -> bool>(&mut self, key: &K, predicate: F) -> Option<bool> {
        let hash = self.hasher.hash_one(key);
        let Ok(entry) = self
            .index
            .find_entry(hash, |&slot| self.slots[slot].key == *key)
        else {
            return None;
        };
        let slot = *entry.get();
        if !predicate(&self.slots[slot].value) {
            self.slots[slot].state.record_hit_mut();
            return Some(false);
        }

        entry.remove();
        self.unlink_resident(slot);
        self.slots[slot].live = false;
        self.free.push(slot);
        Some(true)
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
        // transfer their owned key; Main and free-slot keys have no history.
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
mod tests;

#[cfg(test)]
mod slot_index_tests;
