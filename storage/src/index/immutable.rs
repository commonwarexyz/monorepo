//! An index for keys that are set once at increasing positions and retired only by position.
//!
//! The index maps each translated key to the positions it was set at. Positions are inserted at
//! or above the index's start and retired in prefix order by [`Index::prune`], which suits
//! append-only logs whose entries are never updated or deleted individually. Entries that must
//! be updated or removed by key belong in [super::unordered] or [super::ordered].
//!
//! Translated keys are kept in arrays indexed by position, so the hash table holds only
//! positions, and pruning retires exactly the pruned positions: each is removed from the table
//! under the key its array slot holds, and an array whose positions are all pruned is dropped
//! whole. No pass over the live entries is ever needed, and the table's allocation is bounded by
//! the most entries live at once.

use crate::translator::Translator;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};
use commonware_utils::handles::Table;
use std::collections::VecDeque;

/// Consecutive positions whose translated keys share one array: large enough that an array's
/// fixed cost is negligible per position, small enough that the array straddling the retained
/// start holds few pruned keys until it is dropped.
const CHUNK_LEN: u64 = 1 << 12;

/// Translated keys of the positions in one chunk.
struct Chunk<K> {
    /// The translated key at each offset through the chunk's last indexed position. Other
    /// offsets hold a copy of some key that is never resolved.
    keys: Vec<K>,
    /// Indexed positions the chunk still holds.
    indexed: usize,
}

/// Positions of retained keys by translated key.
pub struct Index<T: Translator> {
    translator: T,
    /// Every indexed position, under the hash of its translated key.
    table: Table<u64>,
    /// Translated keys by position, for the consecutive chunks starting at `first_chunk`.
    chunks: VecDeque<Chunk<T::Key>>,
    /// The chunk holding `start`, which is the chunk `chunks[0]` describes.
    first_chunk: u64,
    /// Positions below this were never indexed or have been retired.
    start: u64,
    items: Gauge,
    pruned: Counter,
}

impl<T: Translator> Index<T> {
    /// Create an empty index for positions at or above `start`, with room for `capacity`
    /// entries before the table grows.
    pub fn new(ctx: impl Metrics, translator: T, start: u64, capacity: usize) -> Self {
        Self {
            translator,
            table: Table::with_capacity(capacity),
            chunks: VecDeque::new(),
            first_chunk: start / CHUNK_LEN,
            start,
            items: ctx.gauge("items", "Number of positions in the index"),
            pruned: ctx.counter("pruned", "Number of positions pruned from the index"),
        }
    }

    /// Return the translated key at `position`, which must be indexed.
    fn key_at(chunks: &VecDeque<Chunk<T::Key>>, first_chunk: u64, position: u64) -> T::Key {
        chunks[(position / CHUNK_LEN - first_chunk) as usize].keys[(position % CHUNK_LEN) as usize]
    }

    /// Index `key` at `position`, which must be at or above the start.
    pub fn insert(&mut self, key: &[u8], position: u64) {
        assert!(
            position >= self.start,
            "position {position} must be at or above the index start {}",
            self.start
        );
        let translated = self.translator.transform(key);

        let chunk_index = position / CHUNK_LEN;
        let offset = (position % CHUNK_LEN) as usize;
        while self.first_chunk + self.chunks.len() as u64 <= chunk_index {
            self.chunks.push_back(Chunk {
                keys: Vec::new(),
                indexed: 0,
            });
        }
        let chunk = &mut self.chunks[(chunk_index - self.first_chunk) as usize];
        if offset < chunk.keys.len() {
            chunk.keys[offset] = translated;
        } else {
            chunk.keys.resize(offset + 1, translated);
        }
        chunk.indexed += 1;

        let (translator, chunks, first_chunk) = (&self.translator, &self.chunks, self.first_chunk);
        self.table
            .insert(translator.hash_one(translated), position, |position| {
                translator.hash_one(Self::key_at(chunks, first_chunk, position))
            });
        self.items.inc();
    }

    /// Return the indexed positions whose translated key is that of `key`, in no particular
    /// order.
    pub fn get(&self, key: &[u8]) -> impl Iterator<Item = u64> + '_ {
        let translated = self.translator.transform(key);
        self.table
            .get(self.translator.hash_one(translated))
            .filter(move |&position| {
                Self::key_at(&self.chunks, self.first_chunk, position) == translated
            })
    }

    /// Retire every indexed position below `start` and drop the key arrays left without
    /// retained positions.
    pub fn prune(&mut self, start: u64) {
        if start <= self.start {
            return;
        }

        // Remove each retired position under the key its slot holds. Slots of unindexed
        // positions hold a key whose entries all carry other positions, so they remove nothing.
        let mut removed = 0u64;
        let mut position = self.start;
        while position < start {
            let chunk_index = position / CHUNK_LEN;
            let chunk_start = chunk_index * CHUNK_LEN;
            let until = start.min(chunk_start + CHUNK_LEN);
            if let Some(chunk) = self
                .chunks
                .get_mut((chunk_index - self.first_chunk) as usize)
            {
                let from = (position - chunk_start) as usize;
                let to = ((until - chunk_start) as usize).min(chunk.keys.len());
                for (offset, key) in chunk.keys.iter().enumerate().take(to).skip(from) {
                    let hash = self.translator.hash_one(*key);
                    if self.table.remove(hash, chunk_start + offset as u64) {
                        removed += 1;
                        chunk.indexed -= 1;
                    }
                }
            }
            position = until;
        }

        let first_chunk = start / CHUNK_LEN;
        while self.first_chunk < first_chunk {
            if let Some(chunk) = self.chunks.pop_front() {
                assert_eq!(
                    chunk.indexed, 0,
                    "a pruned chunk must hold no indexed positions"
                );
            }
            self.first_chunk += 1;
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
            // Two keys collide under TwoCap; the third does not.
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
            // Keys at positions 1, 3, CHUNK_LEN - 1, CHUNK_LEN, 3 * CHUNK_LEN + 5 interleave with
            // unindexed positions and leave the chunk in between empty.
            let indexed = [1, 3, CHUNK_LEN - 1, CHUNK_LEN, 3 * CHUNK_LEN + 5];
            for (i, &position) in indexed.iter().enumerate() {
                index.insert(&[i as u8; 8], position);
            }
            assert_eq!(index.len(), 5);

            // A start between positions retires only those below it.
            index.prune(2);
            assert_eq!(index.len(), 4);
            assert!(positions(&index, &[0u8; 8]).is_empty());
            assert_eq!(positions(&index, &[1u8; 8]), [3]);
            assert_eq!(index.pruned.get(), 1);

            // A start below the retired start does nothing.
            index.prune(1);
            assert_eq!(index.len(), 4);

            // A start past whole chunks drops them and keeps the position at the start itself.
            index.prune(CHUNK_LEN);
            assert_eq!(index.len(), 2);
            assert_eq!(index.first_chunk, 1);
            assert_eq!(positions(&index, &[3u8; 8]), [CHUNK_LEN]);
            assert_eq!(positions(&index, &[4u8; 8]), [3 * CHUNK_LEN + 5]);

            // A start past every chunk empties the index.
            index.prune(4 * CHUNK_LEN);
            assert!(index.is_empty());
            assert!(index.chunks.is_empty());
            assert_eq!(index.first_chunk, 4);
            assert_eq!(index.pruned.get(), 5);

            // Later positions index normally.
            index.insert(&[9u8; 8], 4 * CHUNK_LEN + 1);
            assert_eq!(positions(&index, &[9u8; 8]), [4 * CHUNK_LEN + 1]);
        });
    }

    #[test_traced]
    fn test_start_above_zero() {
        deterministic::Runner::default().start(|context| async move {
            let start = 10 * CHUNK_LEN + 7;
            let mut index = Index::new(context, EightCap, start, 0);
            index.insert(b"first___", start);
            index.insert(b"second__", start + CHUNK_LEN);
            assert_eq!(positions(&index, b"first___"), [start]);

            index.prune(start + 1);
            assert!(positions(&index, b"first___").is_empty());
            assert_eq!(positions(&index, b"second__"), [start + CHUNK_LEN]);
            assert_eq!(index.len(), 1);
        });
    }

    #[test_traced]
    fn test_growth_rehashes_through_the_key_arrays() {
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

            // Retire the first half exactly, including a partial chunk.
            index.prune(20_001);
            assert_eq!(index.len(), 10_000);
            assert!(!positions(&index, &key(0)).contains(&1));
            assert!(positions(&index, &key(10_000)).contains(&20_001));
            assert!(positions(&index, &key(19_999)).contains(&39_999));
            assert_eq!(index.pruned.get(), 10_000);
        });
    }
}
