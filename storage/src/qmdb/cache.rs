//! A fixed-capacity `(location -> key)` cache for snapshot builds.
//!
//! Locations are monotonically increasing log positions that a build looks up at most once each,
//! ignoring translated-key collisions: a key's next update probes the location of its previous
//! update, which is then superseded, so an entry's usefulness decays with its age. The cache is
//! a set-associative array. A location hashes to one set of [`WAYS`] slots, and a full set evicts
//! its oldest location, which tracks FIFO by age without per-entry policy state or a
//! general-purpose hash table. Entries store the full location and key, so lookups are exact.

use commonware_utils::GOLDEN_RATIO;
use core::num::NonZeroUsize;

/// Slots per set. Wide enough that oldest-in-set eviction tracks global FIFO closely, at two
/// cache lines of locations per lookup.
const WAYS: usize = 16;

/// Marks an empty slot. Operation locations are leaf indices, bounded by the family's maximum
/// leaf count (`2^62` for MMR and `2^62 + 30` for MMB), so `u64::MAX` is unreachable.
const EMPTY: u64 = u64::MAX;

/// Maps operation locations to their keys up to a fixed entry capacity.
pub(crate) struct Cache<K> {
    /// Slot locations; slot `i` belongs to set `i / ways`.
    locations: Vec<u64>,
    /// Slot keys, parallel to `locations`.
    keys: Vec<Option<K>>,
    /// Number of sets.
    sets: u64,
    /// Slots per set: [`WAYS`], or the whole capacity when it is smaller than one set.
    ways: usize,
}

impl<K> Cache<K> {
    /// Creates a cache holding at most `capacity` entries, rounded down to whole sets.
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        let capacity = capacity.get();
        let ways = WAYS.min(capacity);
        let sets = capacity / ways;
        let slots = sets * ways;
        Self {
            locations: vec![EMPTY; slots],
            keys: (0..slots).map(|_| None).collect(),
            sets: sets as u64,
            ways,
        }
    }

    /// Returns the first slot of the set for `location`.
    const fn set_start(&self, location: u64) -> usize {
        // A multiplicative hash spreads partition-routed locations across sets, and the
        // multiply-high range reduction maps it onto exactly `sets` without a division.
        let hash = location.wrapping_mul(GOLDEN_RATIO);
        let set = ((hash as u128 * self.sets as u128) >> 64) as usize;
        set * self.ways
    }

    /// Returns the slot holding `location`, if any.
    fn slot(&self, location: u64) -> Option<usize> {
        let start = self.set_start(location);
        self.locations[start..start + self.ways]
            .iter()
            .position(|&resident| resident == location)
            .map(|offset| start + offset)
    }

    /// Returns the key cached for `location`.
    pub(crate) fn get(&self, location: u64) -> Option<&K> {
        self.slot(location).and_then(|i| self.keys[i].as_ref())
    }

    /// Caches `key` for `location`.
    ///
    /// Replaces an existing entry for the same location, otherwise fills an empty slot in the
    /// set, otherwise evicts the set's entry with the oldest location.
    ///
    /// # Panics
    ///
    /// Panics if `location` is `u64::MAX`, which marks empty slots.
    pub(crate) fn put(&mut self, location: u64, key: K) {
        assert!(
            location != EMPTY,
            "location {location} is reserved for empty slots"
        );
        let start = self.set_start(location);
        let mut empty = None;
        let mut oldest = (EMPTY, start);
        for i in start..start + self.ways {
            let resident = self.locations[i];
            if resident == location {
                self.keys[i] = Some(key);
                return;
            }
            if resident == EMPTY {
                empty.get_or_insert(i);
            } else if resident < oldest.0 {
                oldest = (resident, i);
            }
        }
        let i = empty.unwrap_or(oldest.1);
        self.locations[i] = location;
        self.keys[i] = Some(key);
    }

    /// Removes the entry for `location`, if any.
    pub(crate) fn remove(&mut self, location: u64) {
        if let Some(i) = self.slot(location) {
            self.locations[i] = EMPTY;
            self.keys[i] = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZUsize;

    fn present(cache: &Cache<u64>, locations: impl IntoIterator<Item = u64>) -> usize {
        locations
            .into_iter()
            .filter(|&loc| cache.get(loc).is_some())
            .count()
    }

    #[test]
    fn test_capacity_is_an_upper_bound() {
        for capacity in [1, 3, 15, 16, 17, 31, 32, 33, 100, 1000] {
            let mut cache = Cache::<u64>::new(NZUsize!(capacity));
            assert!(cache.locations.len() <= capacity);
            let inserted = 10 * capacity as u64;
            for loc in 0..inserted {
                cache.put(loc, loc);
            }
            assert!(present(&cache, 0..inserted) <= capacity);
        }
    }

    #[test]
    fn test_get_put_remove() {
        let mut cache = Cache::<&str>::new(NZUsize!(16));
        assert!(cache.get(7).is_none());
        cache.put(7, "a");
        assert_eq!(cache.get(7), Some(&"a"));
        cache.put(7, "b");
        assert_eq!(cache.get(7), Some(&"b"));
        cache.remove(7);
        assert!(cache.get(7).is_none());
        cache.remove(7);
        assert!(cache.get(7).is_none());
    }

    #[test]
    fn test_overwrite_leaves_single_entry() {
        // Fill a one-set cache so a later overwrite has both a hole and a match to choose from.
        let mut cache = Cache::new(NZUsize!(16));
        for loc in 0..16 {
            cache.put(loc, loc);
        }
        cache.remove(0);
        cache.put(5, 500);
        assert_eq!(cache.get(5), Some(&500));
        cache.remove(5);
        assert!(cache.get(5).is_none());
        assert_eq!(present(&cache, 0..16), 14);
    }

    #[test]
    fn test_full_set_evicts_oldest_location() {
        let mut cache = Cache::new(NZUsize!(16));
        for loc in 0..16 {
            cache.put(loc, loc);
        }
        cache.put(100, 100);
        assert!(cache.get(0).is_none());
        assert_eq!(present(&cache, 1..16), 15);
        assert_eq!(cache.get(100), Some(&100));
    }

    #[test]
    fn test_eviction_is_confined_to_its_set() {
        let mut cache = Cache::new(NZUsize!(2 * WAYS));
        let (first, second): (Vec<_>, Vec<_>) =
            (0..(4 * WAYS) as u64).partition(|&loc| cache.set_start(loc) == 0);
        assert!(first.len() > WAYS && second.len() > WAYS);

        for &loc in first[..WAYS].iter().chain(&second[..WAYS]) {
            cache.put(loc, loc);
        }
        cache.put(second[WAYS], second[WAYS]);

        assert!(cache.get(second[0]).is_none());
        for &loc in first[..WAYS].iter().chain(&second[1..=WAYS]) {
            assert_eq!(cache.get(loc), Some(&loc));
        }
    }

    #[test]
    fn test_empty_slot_is_used_before_eviction() {
        let mut cache = Cache::new(NZUsize!(16));
        for loc in 0..16 {
            cache.put(loc, loc);
        }
        cache.remove(3);
        cache.put(100, 100);
        assert_eq!(cache.get(0), Some(&0));
        assert!(cache.get(3).is_none());
        assert_eq!(cache.get(100), Some(&100));
    }

    #[test]
    fn test_small_capacity_holds_one_entry() {
        let mut cache = Cache::new(NZUsize!(1));
        assert_eq!(cache.locations.len(), 1);
        cache.put(1, 1);
        cache.put(2, 2);
        assert!(cache.get(1).is_none());
        assert_eq!(cache.get(2), Some(&2));
    }

    #[test]
    #[should_panic(expected = "reserved for empty slots")]
    fn test_put_rejects_empty_marker() {
        let mut cache = Cache::new(NZUsize!(16));
        cache.put(u64::MAX, 0);
    }
}
