//! The key index of an [Immutable](super::Immutable) database.
//!
//! The index maps the translated key of every retained [Operation::Set](super::Operation::Set)
//! to the operation's location. Keys are kept in arrays indexed by location, so the hash table
//! holds only locations, and pruning retires exactly the pruned locations: each is removed from
//! the table under the key its array slot holds, and an array whose locations are all pruned is
//! dropped whole. No pass over the live entries is ever needed, and the table's allocation is
//! bounded by the most entries live at once.

use crate::{
    merkle::{Family, Location},
    translator::Translator,
};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};
use commonware_utils::handles::Table;
use core::marker::PhantomData;
use std::collections::VecDeque;

/// Consecutive locations whose translated keys share one array.
const CHUNK_LEN: u64 = 1 << 12;

/// Translated keys of the operations in one chunk of locations.
struct Chunk<K> {
    /// The translated key at each offset through the chunk's last indexed set. Offsets of other
    /// operations hold a copy of some key that is never resolved.
    keys: Vec<K>,
    /// Indexed sets the chunk still holds.
    sets: usize,
}

/// Locations of retained sets by translated key.
pub(crate) struct Snapshot<F: Family, T: Translator> {
    translator: T,
    /// The location of every indexed set, under the hash of its translated key.
    table: Table<u64>,
    /// Translated keys by location, for the consecutive chunks starting at `first_chunk`.
    chunks: VecDeque<Chunk<T::Key>>,
    /// The chunk holding `start`, which is the chunk `chunks[0]` describes.
    first_chunk: u64,
    /// Locations below this were never indexed or have been retired.
    start: u64,
    items: Gauge,
    pruned: Counter,
    _family: PhantomData<F>,
}

impl<F: Family, T: Translator> Snapshot<F, T> {
    /// Create an empty snapshot for locations at or above `start`, with room for `capacity`
    /// entries before the table grows.
    pub(crate) fn new(
        ctx: impl Metrics,
        translator: T,
        start: Location<F>,
        capacity: usize,
    ) -> Self {
        Self {
            translator,
            table: Table::with_capacity(capacity),
            chunks: VecDeque::new(),
            first_chunk: *start / CHUNK_LEN,
            start: *start,
            items: ctx.gauge("items", "Number of locations in the snapshot"),
            pruned: ctx.counter("pruned", "Number of locations pruned from the snapshot"),
            _family: PhantomData,
        }
    }

    /// Return the translated key of the set at `loc`, which must be indexed.
    fn key_at(chunks: &VecDeque<Chunk<T::Key>>, first_chunk: u64, loc: u64) -> T::Key {
        chunks[(loc / CHUNK_LEN - first_chunk) as usize].keys[(loc % CHUNK_LEN) as usize]
    }

    /// Index the set of `key` at `loc`, which must be at or above the start.
    pub(crate) fn insert(&mut self, key: &[u8], loc: Location<F>) {
        let loc = *loc;
        assert!(loc >= self.start, "location {loc} is below the snapshot start {}", self.start);
        let translated = self.translator.transform(key);

        let chunk_index = loc / CHUNK_LEN;
        let offset = (loc % CHUNK_LEN) as usize;
        while self.first_chunk + self.chunks.len() as u64 <= chunk_index {
            self.chunks.push_back(Chunk {
                keys: Vec::new(),
                sets: 0,
            });
        }
        let chunk = &mut self.chunks[(chunk_index - self.first_chunk) as usize];
        if offset < chunk.keys.len() {
            chunk.keys[offset] = translated;
        } else {
            chunk.keys.resize(offset + 1, translated);
        }
        chunk.sets += 1;

        let (translator, chunks, first_chunk) = (&self.translator, &self.chunks, self.first_chunk);
        self.table.insert(translator.hash_one(translated), loc, |loc| {
            translator.hash_one(Self::key_at(chunks, first_chunk, loc))
        });
        self.items.inc();
    }

    /// Return the indexed locations whose translated key is that of `key`, oldest first.
    pub(crate) fn get(&self, key: &[u8]) -> impl Iterator<Item = Location<F>> + '_ {
        let translated = self.translator.transform(key);
        self.table
            .get(self.translator.hash_one(translated))
            .filter(move |&loc| Self::key_at(&self.chunks, self.first_chunk, loc) == translated)
            .map(Location::new)
    }

    /// Retire every indexed location below `start` and drop the key arrays left without
    /// retained locations.
    pub(crate) fn prune(&mut self, start: Location<F>) {
        let start = *start;
        if start <= self.start {
            return;
        }

        // Remove each retired set under the key its slot holds. Slots of other operations hold
        // a key whose entries all carry different locations, so they remove nothing.
        let mut removed = 0u64;
        let mut loc = self.start;
        while loc < start {
            let chunk_index = loc / CHUNK_LEN;
            let chunk_start = chunk_index * CHUNK_LEN;
            let until = start.min(chunk_start + CHUNK_LEN);
            if let Some(chunk) = self
                .chunks
                .get_mut((chunk_index - self.first_chunk) as usize)
            {
                let from = (loc - chunk_start) as usize;
                let to = ((until - chunk_start) as usize).min(chunk.keys.len());
                for (offset, key) in chunk.keys.iter().enumerate().take(to).skip(from) {
                    let hash = self.translator.hash_one(*key);
                    if self.table.remove(hash, chunk_start + offset as u64) {
                        removed += 1;
                        chunk.sets -= 1;
                    }
                }
            }
            loc = until;
        }

        let first_chunk = start / CHUNK_LEN;
        while self.first_chunk < first_chunk {
            if let Some(chunk) = self.chunks.pop_front() {
                assert_eq!(chunk.sets, 0, "pruned chunk still has indexed sets");
            }
            self.first_chunk += 1;
        }
        self.start = start;
        self.items.dec_by(removed as i64);
        self.pruned.inc_by(removed);
    }

    /// Return the number of indexed locations.
    #[cfg(test)]
    pub(crate) const fn items(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        translator::{EightCap, TwoCap},
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::GOLDEN_RATIO;
    use core::hash::BuildHasher as _;

    type Snap<T> = Snapshot<mmr::Family, T>;

    fn locs<T: Translator>(snapshot: &Snap<T>, key: &[u8]) -> Vec<u64> {
        let mut locs: Vec<u64> = snapshot.get(key).map(|loc| *loc).collect();
        locs.sort_unstable();
        locs
    }

    #[test_traced]
    fn test_get_confirms_translated_key() {
        deterministic::Runner::default().start(|context| async move {
            let mut snapshot = Snap::new(context, TwoCap, Location::new(0), 0);
            // Two keys collide under TwoCap; the third does not.
            snapshot.insert(b"aa1", Location::new(1));
            snapshot.insert(b"aa2", Location::new(3));
            snapshot.insert(b"bb1", Location::new(4));

            assert_eq!(locs(&snapshot, b"aa1"), [1, 3]);
            assert_eq!(locs(&snapshot, b"aa9"), [1, 3]);
            assert_eq!(locs(&snapshot, b"bb1"), [4]);
            assert!(locs(&snapshot, b"cc1").is_empty());
            assert_eq!(snapshot.items(), 3);
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

            let mut snapshot = Snap::new(context, EightCap, Location::new(0), 0);
            let (h1, h2) = (
                snapshot.translator.hash_one(k1),
                snapshot.translator.hash_one(k2),
            );
            assert_eq!(h2, h1.wrapping_add(1 << 16));
            assert_eq!(h1 >> 56, h2 >> 56);

            snapshot.insert(&k1.to_be_bytes(), Location::new(1));
            snapshot.insert(&k2.to_be_bytes(), Location::new(3));
            assert_eq!(locs(&snapshot, &k1.to_be_bytes()), [1]);
            assert_eq!(locs(&snapshot, &k2.to_be_bytes()), [3]);
        });
    }

    #[test_traced]
    fn test_prune_retires_exactly_the_pruned_locations() {
        deterministic::Runner::default().start(|context| async move {
            let mut snapshot = Snap::new(context, EightCap, Location::new(0), 0);
            // Sets at locations 1, 3, CHUNK_LEN - 1, CHUNK_LEN, 3 * CHUNK_LEN + 5 interleave
            // with unindexed operations and leave the chunk in between empty.
            let sets = [1, 3, CHUNK_LEN - 1, CHUNK_LEN, 3 * CHUNK_LEN + 5];
            for (i, &loc) in sets.iter().enumerate() {
                snapshot.insert(&[i as u8; 8], Location::new(loc));
            }
            assert_eq!(snapshot.items(), 5);

            // A start between sets retires only those below it.
            snapshot.prune(Location::new(2));
            assert_eq!(snapshot.items(), 4);
            assert!(locs(&snapshot, &[0u8; 8]).is_empty());
            assert_eq!(locs(&snapshot, &[1u8; 8]), [3]);
            assert_eq!(snapshot.pruned.get(), 1);

            // A start below the retired start does nothing.
            snapshot.prune(Location::new(1));
            assert_eq!(snapshot.items(), 4);

            // A start past whole chunks drops them and keeps the set at the start itself.
            snapshot.prune(Location::new(CHUNK_LEN));
            assert_eq!(snapshot.items(), 2);
            assert_eq!(snapshot.first_chunk, 1);
            assert_eq!(locs(&snapshot, &[3u8; 8]), [CHUNK_LEN]);
            assert_eq!(locs(&snapshot, &[4u8; 8]), [3 * CHUNK_LEN + 5]);

            // A start past every chunk empties the index.
            snapshot.prune(Location::new(4 * CHUNK_LEN));
            assert_eq!(snapshot.items(), 0);
            assert!(snapshot.chunks.is_empty());
            assert_eq!(snapshot.first_chunk, 4);
            assert_eq!(snapshot.pruned.get(), 5);

            // Later sets index normally.
            snapshot.insert(&[9u8; 8], Location::new(4 * CHUNK_LEN + 1));
            assert_eq!(locs(&snapshot, &[9u8; 8]), [4 * CHUNK_LEN + 1]);
        });
    }

    #[test_traced]
    fn test_start_above_zero() {
        deterministic::Runner::default().start(|context| async move {
            let start = 10 * CHUNK_LEN + 7;
            let mut snapshot = Snap::new(context, EightCap, Location::new(start), 0);
            snapshot.insert(b"first___", Location::new(start));
            snapshot.insert(b"second__", Location::new(start + CHUNK_LEN));
            assert_eq!(locs(&snapshot, b"first___"), [start]);

            snapshot.prune(Location::new(start + 1));
            assert!(locs(&snapshot, b"first___").is_empty());
            assert_eq!(locs(&snapshot, b"second__"), [start + CHUNK_LEN]);
            assert_eq!(snapshot.items(), 1);
        });
    }

    #[test_traced]
    fn test_growth_rehashes_through_the_key_arrays() {
        deterministic::Runner::default().start(|context| async move {
            // Enough keys to grow the table several times, four per translated key under TwoCap.
            let mut snapshot = Snap::new(context, TwoCap, Location::new(0), 0);
            let key = |i: u32| {
                let [hi, lo] = ((i % 5_000) as u16).to_be_bytes();
                [hi, lo, (i / 5_000) as u8]
            };
            for i in 0..20_000u32 {
                snapshot.insert(&key(i), Location::new(2 * i as u64 + 1));
            }
            assert_eq!(snapshot.items(), 20_000);
            for i in (0..20_000u32).step_by(997) {
                assert!(locs(&snapshot, &key(i)).contains(&(2 * i as u64 + 1)));
            }

            // Retire the first half exactly, including a partial chunk.
            snapshot.prune(Location::new(20_001));
            assert_eq!(snapshot.items(), 10_000);
            assert!(!locs(&snapshot, &key(0)).contains(&1));
            assert!(locs(&snapshot, &key(10_000)).contains(&20_001));
            assert!(locs(&snapshot, &key(19_999)).contains(&39_999));
            assert_eq!(snapshot.pruned.get(), 10_000);
        });
    }
}
