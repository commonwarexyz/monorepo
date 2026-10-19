//! An open-addressing multimap from 64-bit hashes to caller-owned handles.
//!
//! [Table] never stores keys. Each entry holds a handle, its probe displacement, and a one-byte
//! fingerprint of its hash, packed into one slot that costs the handle plus four bytes and that a
//! probe reads with a single access. The caller keeps keys elsewhere, resolving each candidate
//! handle to its key to confirm a lookup and mapping existing handles back to their hashes when
//! the table grows. A lookup is therefore a candidate generator that yields every entry inserted
//! under the requested hash, plus any entry whose different hash shares the same home slot and
//! fingerprint.
//!
//! The low bits of a hash select its home slot and the top byte is its fingerprint, so hashes must
//! be well distributed in both (use a keyed hasher for adversarial keys).
//!
//! ```text
//! hash  |  fingerprint: top byte  |              ...              | home: low bits |
//!
//! slot  |  displacement: 24 bits  | fingerprint: 8 bits |          handle          |
//!       |<---------------- meta: u32 ------------------>|<---------- H ---------->|
//! ```
//!
//! # Robin Hood Ordering
//!
//! Within each run of occupied slots, entries are sorted by home slot. All entries with a given
//! home are therefore adjacent, each exactly its displacement away from that home, so a lookup
//! stops as soon as it reaches an empty slot or an entry closer to its own home.
//!
//! ```text
//! slot            4       5       6       7       8       9
//!              +-------+-------+-------+-------+-------+-------+
//! home         |   4   |   4   |   5   |   7   |   7   | empty |
//! displacement |   0   |   1   |   1   |   0   |   1   |       |
//!              +-------+-------+-------+-------+-------+-------+
//!
//! get(hash with home 5) walks from slot 5. Slot 5 holds a home-4 entry at displacement 1,
//! which is not at displacement 0 and so is not a candidate. Slot 6 holds a home-5 entry at
//! displacement 1, yielded if its fingerprint matches. Slot 7 holds an entry at displacement 0,
//! closer to its home than the walk's distance of 2, so the walk stops.
//!
//! remove(the entry at slot 5) shifts slot 6 back into slot 5 (displacement 1 -> 0) and stops at
//! slot 7, whose entry is already at its home.
//! ```
//!
//! Removal uses backward-shift deletion, so the following entries of the run, up to the next
//! entry already at its home, move back one slot. No tombstones exist, so removals never
//! lengthen probes or force a rebuild, and the allocation depends only on the number of entries
//! that have been live at once. The table never shrinks.
//!
//! Entries that share a hash occupy one contiguous run, so inserting or removing one of them
//! costs time linear in the run's length.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::iter;

/// Metadata of an unoccupied slot.
///
/// Its displacement (0xFF_FFFF) exceeds [MAX_DISPLACEMENT], so no occupied slot can equal it.
const EMPTY: u32 = u32::MAX;

/// Largest displacement an entry may have.
///
/// Entries sharing a home slot sit at consecutive displacements, so this also bounds how many
/// entries may share the low bits of their hashes.
const MAX_DISPLACEMENT: u32 = (1 << 24) - 2;

/// One unit of displacement in slot metadata.
const DISPLACEMENT_UNIT: u32 = 1 << 8;

/// Slot count after the first allocation.
const MIN_SLOTS: usize = 16;

/// Returns the slot metadata of an entry for `hash` at `displacement` from its home.
#[inline]
const fn slot_meta(hash: u64, displacement: u32) -> u32 {
    (displacement << 8) | (hash >> 56) as u32
}

/// One slot of a [Table]: an entry's metadata and handle, packed so a probe reads one place.
#[repr(C, packed)]
struct Slot<H> {
    /// Displacement (high 24 bits) and fingerprint (low byte), or EMPTY when unoccupied.
    meta: u32,
    /// The handle, meaningful only when the slot is occupied.
    handle: H,
}

impl<H: Copy> Clone for Slot<H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: Copy> Copy for Slot<H> {}

/// An open-addressing multimap from 64-bit hashes to caller-owned handles.
///
/// See the [module documentation](self) for the lookup contract.
///
/// # Example
///
/// ```
/// use commonware_utils::handles::Table;
///
/// // FNV-1a stands in for a keyed hasher.
/// fn hash(key: &str) -> u64 {
///     key.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
///         (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
///     })
/// }
///
/// let keys = ["apple", "banana", "cherry"];
/// let mut table = Table::new();
/// for (handle, key) in keys.iter().enumerate() {
///     table.insert(hash(key), handle, |handle| hash(keys[handle]));
/// }
///
/// // Confirm each candidate against the key it resolves to.
/// let find = |table: &Table<usize>, key| table.get(hash(key)).find(|&handle| keys[handle] == key);
/// assert_eq!(find(&table, "banana"), Some(1));
/// assert!(table.remove(hash("banana"), 1));
/// assert_eq!(find(&table, "banana"), None);
/// ```
pub struct Table<H> {
    /// The slots: a power of two of them, or none before the first allocation.
    slots: Vec<Slot<H>>,
    len: usize,
}

impl<H> core::fmt::Debug for Table<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Table")
            .field("len", &self.len)
            .field("slots", &self.slots.len())
            .finish()
    }
}

impl<H: Copy + Eq + Default> Table<H> {
    /// Creates an empty table without allocating.
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }

    /// Creates an empty table that fits `entries` entries without growing.
    ///
    /// # Panics
    ///
    /// Panics if the required slot count overflows `usize`.
    pub fn with_capacity(entries: usize) -> Self {
        if entries == 0 {
            return Self::new();
        }
        let slots = entries
            .checked_mul(4)
            .and_then(|scaled| scaled.div_ceil(3).checked_next_power_of_two())
            .expect("capacity overflow")
            .max(MIN_SLOTS);
        Self {
            slots: Self::empty_slots(slots),
            len: 0,
        }
    }

    /// Returns `count` unoccupied slots.
    fn empty_slots(count: usize) -> Vec<Slot<H>> {
        vec![
            Slot {
                meta: EMPTY,
                handle: H::default(),
            };
            count
        ]
    }

    /// Returns the number of entries.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the table has no entries.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of entries that fit before the next growth.
    pub const fn capacity(&self) -> usize {
        self.slots.len() * 3 / 4
    }

    /// Returns the handles whose home slot and fingerprint match `hash`, in probe order.
    ///
    /// Every handle inserted under `hash` is yielded. Callers confirm each candidate against the
    /// key it resolves to, since entries with a different hash that shares the home slot and
    /// fingerprint are yielded too.
    #[inline]
    pub fn get(&self, hash: u64) -> impl Iterator<Item = H> + '_ {
        self.probe(hash).map(|slot| self.slots[slot].handle)
    }

    /// Inserts `handle` under `hash`.
    ///
    /// Duplicate hashes and duplicate handles are allowed. `rehash` must map every handle already
    /// in the table to the hash it was inserted under, and it is called only when the table grows.
    ///
    /// # Panics
    ///
    /// Panics if an entry would end up more than 2^24 - 2 slots from its home, which takes a run
    /// of 2^24 occupied slots (for example, 2^24 entries with identical hashes).
    #[inline]
    pub fn insert(&mut self, hash: u64, handle: H, mut rehash: impl FnMut(H) -> u64) {
        if self.len == self.capacity() {
            self.grow(&mut rehash);
        }
        self.place(hash, handle);
        self.len += 1;
    }

    /// Removes one entry holding `handle` whose home slot and fingerprint match `hash`, returning
    /// whether one existed.
    ///
    /// `hash` must be the hash the entry was inserted under. Like [Table::get], matching is by
    /// home slot and fingerprint, so a different hash sharing both would remove the entry too.
    #[inline]
    pub fn remove(&mut self, hash: u64, handle: H) -> bool {
        let Some(mut hole) = self.probe(hash).find(|&slot| {
            let candidate = self.slots[slot].handle;
            candidate == handle
        }) else {
            return false;
        };

        // Shift the rest of the run back one slot, stopping before an entry already at home.
        let mask = self.slots.len() - 1;
        loop {
            let next = (hole + 1) & mask;
            let slot = self.slots[next];
            let meta = slot.meta;
            if meta == EMPTY || meta < DISPLACEMENT_UNIT {
                break;
            }
            self.slots[hole] = Slot {
                meta: meta - DISPLACEMENT_UNIT,
                handle: slot.handle,
            };
            hole = next;
        }
        self.slots[hole].meta = EMPTY;
        self.len -= 1;
        true
    }

    /// Returns the slots holding entries with the home slot and fingerprint of `hash`.
    ///
    /// Such entries sit exactly at their probe distance. The walk ends at an empty slot or at an
    /// entry closer to its home, one of which exists within [MAX_DISPLACEMENT] + 1 steps.
    #[inline]
    fn probe(&self, hash: u64) -> impl Iterator<Item = usize> + '_ {
        let mask = self.slots.len().wrapping_sub(1);
        let mut slot = hash as usize & mask;
        let mut displacement = 0;
        iter::from_fn(move || {
            loop {
                let meta = self.slots.get(slot)?.meta;
                if meta == EMPTY || meta >> 8 < displacement {
                    return None;
                }
                let current = slot;
                let matched = meta == slot_meta(hash, displacement);
                slot = (slot + 1) & mask;
                displacement += 1;
                if matched {
                    return Some(current);
                }
            }
        })
    }

    /// Places an entry in Robin Hood order without changing `len`.
    ///
    /// The entry goes before the first entry closer to its home (or into the first empty slot),
    /// and the rest of the run shifts forward one slot.
    ///
    /// Requires an empty slot.
    #[inline]
    fn place(&mut self, hash: u64, handle: H) {
        const OVERFLOW: &str = "too many entries share the low bits of their hashes";
        let mask = self.slots.len() - 1;
        let mut slot = hash as usize & mask;

        // Find the insertion point.
        let mut displacement = 0;
        loop {
            let meta = self.slots[slot].meta;
            if meta == EMPTY || meta >> 8 < displacement {
                break;
            }
            assert!(displacement < MAX_DISPLACEMENT, "{OVERFLOW}");
            slot = (slot + 1) & mask;
            displacement += 1;
        }
        let target = slot;

        // Find the end of the run, checking that every entry can shift.
        loop {
            let meta = self.slots[slot].meta;
            if meta == EMPTY {
                break;
            }
            assert!(meta >> 8 < MAX_DISPLACEMENT, "{OVERFLOW}");
            slot = (slot + 1) & mask;
        }

        // Shift the run forward into the empty slot and fill the insertion point.
        while slot != target {
            let previous = slot.wrapping_sub(1) & mask;
            let moved = self.slots[previous];
            self.slots[slot] = Slot {
                meta: moved.meta + DISPLACEMENT_UNIT,
                handle: moved.handle,
            };
            slot = previous;
        }
        self.slots[target] = Slot {
            meta: slot_meta(hash, displacement),
            handle,
        };
    }

    /// Rebuilds the table with twice as many slots.
    fn grow(&mut self, rehash: &mut impl FnMut(H) -> u64) {
        let mut table = Self {
            slots: Self::empty_slots((self.slots.len() * 2).max(MIN_SLOTS)),
            len: self.len,
        };
        for slot in &self.slots {
            let slot = *slot;
            if slot.meta != EMPTY {
                table.place(rehash(slot.handle), slot.handle);
            }
        }
        *self = table;
    }
}

impl<H: Copy + Eq + Default> Default for Table<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TestRng, test_rng};
    use core::cell::Cell;
    use rand::{Rng as _, RngExt as _};
    use std::collections::BTreeMap;

    impl<H: Copy + Eq + Default> Table<H> {
        /// Returns the metadata of every slot.
        fn metas(&self) -> Vec<u32> {
            self.slots.iter().map(|slot| slot.meta).collect()
        }

        /// Asserts slot metadata, Robin Hood order, and `len` agree with each handle's hash.
        fn check_invariants(&self, hash_of: impl Fn(H) -> u64) {
            let slots = self.slots.len();
            assert_eq!(self.capacity(), slots * 3 / 4);
            assert!(self.len <= self.capacity());
            if slots == 0 {
                return;
            }
            assert!(slots.is_power_of_two() && slots >= MIN_SLOTS);
            let mask = slots - 1;
            let mut occupied = 0;
            for (slot, entry) in self.slots.iter().enumerate() {
                let entry = *entry;
                let (meta, handle) = (entry.meta, entry.handle);
                if meta == EMPTY {
                    continue;
                }
                occupied += 1;
                let hash = hash_of(handle);
                let displacement = slot.wrapping_sub(hash as usize) & mask;
                assert!(displacement <= MAX_DISPLACEMENT as usize);
                assert_eq!(meta, slot_meta(hash, displacement as u32));

                // Each entry is at most one slot further from its home than its predecessor.
                let next = self.slots[(slot + 1) & mask].meta;
                assert!(next == EMPTY || next >> 8 <= (meta >> 8) + 1);
            }
            assert_eq!(occupied, self.len);
        }
    }

    /// Spreads `i` across all 64 bits.
    const fn spread(i: u64) -> u64 {
        i.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }

    fn sorted<H: Ord>(handles: impl Iterator<Item = H>) -> Vec<H> {
        let mut handles: Vec<H> = handles.collect();
        handles.sort();
        handles
    }

    #[test]
    fn test_basic_insert_get_remove() {
        // Handles 0 and 1 share a hash, and handle 4 is never inserted.
        let hashes = [spread(1), spread(1), spread(2), spread(3), spread(4)];
        let rehash = |handle: usize| hashes[handle];
        let mut table = Table::new();
        assert!(table.is_empty());
        assert_eq!(table.slots.capacity(), 0);
        assert_eq!(table.get(hashes[0]).next(), None);
        assert!(!table.remove(hashes[0], 0));

        for (handle, &hash) in hashes.iter().enumerate().take(4) {
            table.insert(hash, handle, rehash);
        }
        assert_eq!(table.len(), 4);
        assert_eq!(sorted(table.get(hashes[0])), [0, 1]);
        assert_eq!(sorted(table.get(hashes[2])), [2]);
        assert_eq!(sorted(table.get(hashes[3])), [3]);
        assert_eq!(table.get(hashes[4]).next(), None);

        // Removing one duplicate leaves the other.
        assert!(table.remove(hashes[0], 0));
        assert_eq!(sorted(table.get(hashes[0])), [1]);
        assert_eq!(table.len(), 3);

        // Removing absent handles changes nothing.
        let metas = table.metas();
        assert!(!table.remove(hashes[0], 0));
        assert!(!table.remove(hashes[4], 4));
        assert_eq!(table.metas(), metas);
        assert_eq!(table.len(), 3);

        // The same handle may be inserted twice under one hash, and is removed once at a time.
        table.insert(hashes[1], 1, rehash);
        assert_eq!(sorted(table.get(hashes[1])), [1, 1]);
        assert!(table.remove(hashes[1], 1));
        assert_eq!(sorted(table.get(hashes[1])), [1]);
        table.check_invariants(rehash);
    }

    #[test]
    fn test_fingerprint_false_candidates() {
        // Hash 1 shares the home slot and fingerprint of hash 0 but differs in its middle bits.
        // Hash 2 shares only the fingerprint, and hash 3 only the home slot.
        let keys = ["a", "b", "c", "d"];
        let hashes = [
            0xAB00_0000_0000_0005,
            0xAB00_0100_0000_0005,
            0xAB00_0000_0000_0006,
            0xCD00_0000_0000_0005,
        ];
        let rehash = |handle: usize| hashes[handle];
        let mut table = Table::new();
        for (handle, &hash) in hashes.iter().enumerate() {
            table.insert(hash, handle, rehash);
        }

        // The table is a candidate generator, so callers resolve each handle to confirm its key.
        assert_eq!(sorted(table.get(hashes[0])), [0, 1]);
        let confirmed: Vec<_> = table.get(hashes[0]).filter(|&h| keys[h] == "a").collect();
        assert_eq!(confirmed, [0]);
        assert_eq!(sorted(table.get(hashes[2])), [2]);
        assert_eq!(sorted(table.get(hashes[3])), [3]);
        table.check_invariants(rehash);
    }

    #[test]
    fn test_growth_rehashes_every_entry() {
        let mut rng = test_rng();
        let mut hashes = Vec::new();
        let calls = Cell::new(0);
        let mut table = Table::new();
        let mut growths = 0;
        for handle in 0..5_000 {
            hashes.push(rng.next_u64());
            let (slots, len, before) = (table.slots.len(), table.len(), calls.get());
            table.insert(hashes[handle], handle, |handle| {
                calls.set(calls.get() + 1);
                hashes[handle]
            });
            assert_eq!(table.len(), handle + 1);
            if table.slots.len() == slots {
                assert_eq!(calls.get(), before);
                continue;
            }

            // Growth doubles once, rehashing every existing entry exactly once.
            growths += 1;
            assert_eq!(table.slots.len(), (slots * 2).max(MIN_SLOTS));
            assert_eq!(len, slots * 3 / 4);
            assert_eq!(calls.get() - before, len);
            table.check_invariants(|handle| hashes[handle]);
            for (handle, &hash) in hashes.iter().enumerate() {
                assert!(table.get(hash).any(|h| h == handle));
            }
        }
        assert_eq!(growths, 10);
        assert_eq!(table.slots.len(), 8_192);
    }

    #[test]
    fn test_shared_hash_run() {
        // Every entry shares one hash, so all sit in one run at consecutive displacements, and
        // the run survives growth and removal from its middle.
        const ENTRIES: usize = 2_000;
        let mut table = Table::new();
        for handle in 0..ENTRIES {
            table.insert(spread(1), handle, |_| spread(1));
        }
        assert_eq!(table.slots.len(), 4_096);
        assert_eq!(table.get(spread(1)).count(), ENTRIES);
        table.check_invariants(|_| spread(1));

        for handle in (0..ENTRIES).step_by(2) {
            assert!(table.remove(spread(1), handle));
        }
        assert_eq!(
            sorted(table.get(spread(1))),
            sorted((1..ENTRIES).step_by(2))
        );
        table.check_invariants(|_| spread(1));
    }

    #[test]
    fn test_matches_multimap_model() {
        const HANDLES: usize = 1_024;
        const HASHES: usize = 512;
        const OPERATIONS: usize = 50_000;
        let mut rng = TestRng::new(5);

        // Paired hashes share their low 24 bits (one home at every reachable size), and
        // fingerprints take four values, so false candidates are common. Handles map to hashes
        // many-to-one, and a handle may be inserted repeatedly.
        let mut pool: Vec<u64> = Vec::with_capacity(HASHES);
        for i in 0..HASHES {
            let fingerprint = rng.random_range(0..4u64) << 56;
            let middle = rng.next_u64() & 0x00FF_FFFF_FF00_0000;
            let low = if i % 2 == 1 {
                pool[i - 1]
            } else {
                rng.next_u64()
            } & 0xFF_FFFF;
            pool.push(fingerprint | middle | low);
        }
        let hash_of: Vec<u64> = (0..HANDLES)
            .map(|_| pool[rng.random_range(0..pool.len())])
            .collect();
        let rehash_calls = Cell::new(0);
        let rehash = |handle: usize| {
            rehash_calls.set(rehash_calls.get() + 1);
            hash_of[handle]
        };

        let mut model: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut table = Table::new();
        let (mut removed, mut false_candidates, mut max_len) = (0, 0, 0);
        for op in 0..OPERATIONS {
            // Alternate phases that favor insertion and removal.
            let inserts = if (op / 5_000) % 2 == 0 { 6 } else { 3 };
            let roll = rng.random_range(0..10);
            let (slots, calls) = (table.slots.len(), rehash_calls.get());
            let hash = if roll < inserts {
                let handle = rng.random_range(0..HANDLES);
                table.insert(hash_of[handle], handle, rehash);
                model.entry(hash_of[handle]).or_default().push(handle);
                hash_of[handle]
            } else if roll < 9 {
                let handle = rng.random_range(0..HANDLES);
                let hash = hash_of[handle];
                let handles = model.get_mut(&hash);
                let position = handles
                    .as_ref()
                    .and_then(|handles| handles.iter().position(|&h| h == handle));
                assert_eq!(table.remove(hash, handle), position.is_some());
                if let (Some(handles), Some(position)) = (handles, position) {
                    handles.swap_remove(position);
                    if handles.is_empty() {
                        model.remove(&hash);
                    }
                    removed += 1;
                }
                hash
            } else if rng.random_bool(0.5) {
                pool[rng.random_range(0..pool.len())]
            } else {
                rng.next_u64()
            };
            if table.slots.len() == slots {
                assert_eq!(rehash_calls.get(), calls);
            }
            assert_eq!(table.len(), model.values().map(Vec::len).sum::<usize>());
            max_len = max_len.max(table.len());

            // Candidates are exactly the entries sharing the home slot and fingerprint.
            let mask = table.slots.len().wrapping_sub(1);
            let expected = sorted(
                model
                    .iter()
                    .filter(|&(&other, _)| {
                        other >> 56 == hash >> 56 && (other ^ hash) & mask as u64 == 0
                    })
                    .flat_map(|(_, handles)| handles.iter().copied()),
            );
            let actual = sorted(table.get(hash));
            assert_eq!(actual, expected);
            false_candidates += actual.iter().filter(|&&h| hash_of[h] != hash).count();

            if op % 1_000 == 0 {
                table.check_invariants(|handle| hash_of[handle]);
            }
        }
        table.check_invariants(|handle| hash_of[handle]);
        assert!(removed > 10_000 && false_candidates > 1_000 && max_len > 2_000);
    }

    #[test]
    fn test_with_capacity_never_rehashes() {
        let table = Table::<u64>::with_capacity(0);
        assert_eq!(table.slots.capacity(), 0);

        let mut rng = test_rng();
        for entries in [1, 12, 13, 100, 384, 385, 1_000] {
            let mut table = Table::with_capacity(entries);
            let slots = table.slots.len();
            assert!(table.capacity() >= entries);
            assert!(slots == MIN_SLOTS || slots / 2 * 3 / 4 < entries);
            for handle in 0..entries {
                table.insert(rng.next_u64(), handle, |_| {
                    unreachable!("rehash without growth")
                });
            }
            assert_eq!(table.slots.len(), slots);
            assert_eq!(table.len(), entries);
        }
    }
}
