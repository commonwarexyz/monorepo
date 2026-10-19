//! An index for keys that are set once at increasing positions and retired only by position.
//!
//! The index maps each translated key to the positions it was set at. Positions are inserted at
//! or above the index's start and retired in prefix order by [`Index::prune`], which suits
//! append-only logs whose entries are never updated or deleted individually. Entries that must
//! be updated or removed by key belong in [super::unordered] or [super::ordered].
//!
//! Translated keys are kept in a ring indexed by position, so the hash table holds only
//! positions, and pruning retires exactly the pruned positions: each is removed from the table
//! under the key its ring slot holds, and the slots are released from the ring's front. No pass
//! over the live entries is ever needed. The table's allocation is bounded by the most keys
//! indexed at once and the ring's by the widest span of positions retained at once, indexed
//! or not.
//!
//! ```text
//!  table: positions under the hash of their key      keys: translated key by position
//!  +----------+-------+                              position  0   1   2   3   4   5   6   7
//!  | hash(aa) | 1, 6  |                                      +---+---+---+---+---+---+---+---+
//!  | hash(c0) | 3     |                                      | - | aa| - | c0| 12| - | aa| - |
//!  | hash(12) | 4     |                                      +---+---+---+---+---+---+---+---+
//!  +----------+-------+                                      ^ start
//!
//!  get(key)   hash(key) gives candidate positions. Those whose key slot holds translate(key)
//!             are returned, so a slot and fingerprint shared with another key costs no read.
//!  prune(5)   for each position in start..5: table.remove(hash(key slot), position). The five
//!             front slots are released, and exactly the keys at 5 and up remain.
//! ```

use crate::translator::Translator;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};
use commonware_utils::{Widen, handles::Table};
use core::cmp::Ordering;
use std::collections::VecDeque;

/// Positions of retained keys by translated key.
pub struct Index<T: Translator> {
    translator: T,
    /// Every indexed position, under the hash of its translated key.
    table: Table<u64>,
    /// The translated key at each position from `start` through the last indexed position.
    /// Positions that were never indexed hold a copy of some key that is never resolved.
    keys: VecDeque<T::Key>,
    /// Positions below this were never indexed or have been retired.
    start: u64,

    items: Gauge,
    pruned: Counter,
}

impl<T: Translator> Index<T> {
    /// Create an empty index for positions at or above `start`, with room for `capacity`
    /// positions before the table or the key ring grows.
    pub fn new(ctx: impl Metrics, translator: T, start: u64, capacity: usize) -> Self {
        Self {
            translator,
            table: Table::with_capacity(capacity),
            keys: VecDeque::with_capacity(capacity),
            start,
            items: ctx.gauge("items", "Number of positions in the index"),
            pruned: ctx.counter("pruned", "Number of positions pruned from the index"),
        }
    }

    /// Return the offset of `position` from `start`, which it must not precede.
    fn offset(start: u64, position: u64) -> usize {
        usize::try_from(position - start).expect("retained positions must fit in usize")
    }

    /// Return the translated key at `position`, which must be indexed.
    fn key_at(keys: &VecDeque<T::Key>, start: u64, position: u64) -> T::Key {
        keys[Self::offset(start, position)]
    }

    /// Index `key` at `position`, which must be at or above the start and not indexed already.
    #[inline]
    pub fn insert(&mut self, key: &[u8], position: u64) {
        assert!(
            position >= self.start,
            "position {position} must be at or above the index start {}",
            self.start
        );
        let translated = self.translator.transform(key);

        // Record the key in the ring. Positions usually arrive in order, but a batch may index
        // them in any order, so extend the ring through this position when it is further ahead,
        // filling the slots skipped on the way with this key.
        let offset = Self::offset(self.start, position);
        match offset.cmp(&self.keys.len()) {
            Ordering::Equal => self.keys.push_back(translated),
            Ordering::Less => self.keys[offset] = translated,
            Ordering::Greater => self.keys.resize(offset + 1, translated),
        }

        // Index the position under the key's hash. The table stores no keys, so only when it
        // grows does it resolve each stored position back to its key through the ring to rehash.
        self.table
            .insert(self.translator.hash_one(translated), position, |position| {
                self.translator
                    .hash_one(Self::key_at(&self.keys, self.start, position))
            });
        self.items.inc();
    }

    /// Return the indexed positions whose translated key is that of `key`, in no particular
    /// order.
    #[inline]
    pub fn get(&self, key: &[u8]) -> impl Iterator<Item = u64> + '_ {
        let translated = self.translator.transform(key);
        self.table
            .get(self.translator.hash_one(translated))
            .filter(move |&position| Self::key_at(&self.keys, self.start, position) == translated)
    }

    /// Retire every indexed position below `start`.
    pub fn prune(&mut self, start: u64) {
        if start <= self.start {
            return;
        }

        // Remove each retired position under the key its slot holds. A slot that was never
        // indexed holds a key whose entries all carry other positions, so it removes nothing.
        let retired = Self::offset(self.start, start).min(self.keys.len());
        let mut removed = 0u64;
        for (offset, key) in self.keys.drain(..retired).enumerate() {
            let hash = self.translator.hash_one(key);
            if self.table.remove(hash, self.start + Widen::widen(offset)) {
                removed += 1;
            }
        }
        self.start = start;
        self.items.dec_by(removed as i64);
        self.pruned.inc_by(removed);
    }

    /// Return the number of indexed positions.
    pub const fn len(&self) -> usize {
        self.table.len()
    }

    /// Return whether no position is indexed.
    pub const fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translator::{EightCap, TwoCap};
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::GOLDEN_RATIO;
    use core::hash::BuildHasher as _;

    fn positions<T: Translator>(index: &Index<T>, key: &[u8]) -> Vec<u64> {
        let mut positions: Vec<u64> = index.get(key).collect();
        positions.sort_unstable();
        positions
    }

    #[test_traced]
    fn test_get_confirms_translated_key() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = Index::new(context, TwoCap, 0, 0);
            // Two keys collide under TwoCap and the third does not.
            index.insert(b"aa1", 1);
            index.insert(b"aa2", 3);
            index.insert(b"bb1", 4);

            assert_eq!(positions(&index, b"aa1"), [1, 3]);
            assert_eq!(positions(&index, b"aa9"), [1, 3]);
            assert_eq!(positions(&index, b"bb1"), [4]);
            assert!(positions(&index, b"cc1").is_empty());
            assert_eq!(index.len(), 3);
        });
    }

    #[test_traced]
    fn test_get_rejects_candidates_sharing_slot_and_fingerprint() {
        deterministic::Runner::default().start(|context| async move {
            // GOLDEN_RATIO's inverse mod 2^64. Adding INVERSE << 16 to a key adds 1 << 16 to its
            // hash, so the keys share a home slot (while the table has at most 2^16 slots) and a
            // fingerprint, and the table yields each as a candidate for the other.
            const INVERSE: u64 = 0xf1de_83e1_9937_733d;
            assert_eq!(GOLDEN_RATIO.wrapping_mul(INVERSE), 1);
            let k1 = 0x1234_5678_9abc_def0u64;
            let k2 = k1.wrapping_add(INVERSE << 16);

            let mut index = Index::new(context, EightCap, 0, 0);
            let (h1, h2) = (index.translator.hash_one(k1), index.translator.hash_one(k2));
            assert_eq!(h2, h1.wrapping_add(1 << 16));
            assert_eq!(h1 >> 56, h2 >> 56);

            index.insert(&k1.to_be_bytes(), 1);
            index.insert(&k2.to_be_bytes(), 3);
            assert_eq!(positions(&index, &k1.to_be_bytes()), [1]);
            assert_eq!(positions(&index, &k2.to_be_bytes()), [3]);
        });
    }

    #[test_traced]
    fn test_prune_retires_exactly_the_pruned_positions() {
        deterministic::Runner::default().start(|context| async move {
            let mut index = Index::new(context, EightCap, 0, 0);
            // Keys at positions 1, 3, 4, 9 and 20 interleave with unindexed positions.
            for (i, position) in [1, 3, 4, 9, 20].into_iter().enumerate() {
                index.insert(&[i as u8; 8], position);
            }
            assert_eq!(index.len(), 5);
            assert_eq!(index.keys.len(), 21);

            // A start between positions retires only those below it and releases their slots.
            index.prune(2);
            assert_eq!(index.len(), 4);
            assert_eq!(index.keys.len(), 19);
            assert!(positions(&index, &[0u8; 8]).is_empty());
            assert_eq!(positions(&index, &[1u8; 8]), [3]);
            assert_eq!(index.pruned.get(), 1);

            // A start below the retired start does nothing.
            index.prune(1);
            assert_eq!(index.len(), 4);

            // A start at an indexed position keeps it.
            index.prune(9);
            assert_eq!(index.len(), 2);
            assert_eq!(positions(&index, &[3u8; 8]), [9]);
            assert_eq!(positions(&index, &[4u8; 8]), [20]);

            // A start past every position empties the index, and later positions index normally.
            index.prune(100);
            assert!(index.is_empty());
            assert!(index.keys.is_empty());
            assert_eq!(index.pruned.get(), 5);
            index.insert(&[9u8; 8], 101);
            assert_eq!(positions(&index, &[9u8; 8]), [101]);
            assert_eq!(index.keys.len(), 2);
        });
    }

    #[test_traced]
    fn test_start_above_zero() {
        deterministic::Runner::default().start(|context| async move {
            let start = 40_967;
            let mut index = Index::new(context, EightCap, start, 0);
            index.insert(b"first___", start);
            index.insert(b"second__", start + 5_000);
            assert_eq!(positions(&index, b"first___"), [start]);

            index.prune(start + 1);
            assert!(positions(&index, b"first___").is_empty());
            assert_eq!(positions(&index, b"second__"), [start + 5_000]);
            assert_eq!(index.len(), 1);
        });
    }

    #[test_traced]
    fn test_growth_rehashes_through_the_keys() {
        deterministic::Runner::default().start(|context| async move {
            // Enough keys to grow the table several times, four per translated key under TwoCap.
            let mut index = Index::new(context, TwoCap, 0, 0);
            let key = |i: u32| {
                let [hi, lo] = ((i % 5_000) as u16).to_be_bytes();
                [hi, lo, (i / 5_000) as u8]
            };
            for i in 0..20_000u32 {
                index.insert(&key(i), 2 * i as u64 + 1);
            }
            assert_eq!(index.len(), 20_000);
            for i in (0..20_000u32).step_by(997) {
                assert!(positions(&index, &key(i)).contains(&(2 * i as u64 + 1)));
            }

            // Retire the first half exactly.
            index.prune(20_001);
            assert_eq!(index.len(), 10_000);
            assert!(!positions(&index, &key(0)).contains(&1));
            assert!(positions(&index, &key(10_000)).contains(&20_001));
            assert!(positions(&index, &key(19_999)).contains(&39_999));
            assert_eq!(index.pruned.get(), 10_000);
        });
    }
}
