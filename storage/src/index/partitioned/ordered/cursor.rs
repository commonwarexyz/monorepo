//! A mutable cursor over a single translated key's values.
//!
//! A [Cursor] iterates and edits the value run for one translated key. That run lives in one of two
//! representations -- an inline sorted-array [Partition] or a spilled `BTreeMap` (see the parent
//! module) -- abstracted behind [Backing]. The iteration protocol (the [State] machine, the
//! must-call-`next` guards, and the metric bookkeeping) is identical for both representations, so it
//! is written once here; [Backing] holds the only thing that differs: the positional store
//! operations.

use super::partition::Partition;
use crate::index::Cursor as CursorTrait;
use commonware_runtime::telemetry::metrics::{Counter, Gauge};
use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    ops::Range,
};

const MUST_CALL_NEXT: &str = "must call Cursor::next()";
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Position of a [Cursor] within its key's value run (offset 0 is the run's first value).
enum State {
    /// Before the first `next()` or after an `insert()`/`delete()`: the next `next()` returns the
    /// value at run offset `from`.
    NeedNext { from: usize },
    /// `next()` returned the value at run offset `offset`; `update`/`delete`/`insert` are valid.
    Active { offset: usize },
    /// `next()` returned `None`; only `insert()` (which appends) is valid.
    Done,
}

/// The store holding a [Cursor]'s value run, abstracting the inline and spilled representations
/// behind a common positional interface. All offsets are relative to the start of the key's run.
enum Backing<'a, K: Ord + Copy, V> {
    /// Inline sorted-array partition: the key's values occupy the contiguous index range `run`.
    ///
    /// `run.start` is fixed for the cursor's lifetime: the cursor borrows the partition exclusively
    /// and only ever adds or removes its own key's values, so nothing shifts the entries before the
    /// run. `run.end` is adjusted by one on each insert/remove to stay aligned with the array.
    Soa {
        partition: &'a mut Partition<K, V>,
        key: K,
        run: Range<usize>,
    },
    /// Spilled partition: the key's values live in the side-table's `BTreeMap`, re-resolved on each
    /// access (spilling is the rare case, so the extra descent is off the hot path).
    Spilled {
        spilled: &'a mut HashMap<usize, BTreeMap<K, Vec<V>>>,
        partition: usize,
        key: K,
    },
}

impl<K: Ord + Copy, V> Backing<'_, K, V> {
    /// The number of values in the run (zero if the key is absent).
    fn len(&self) -> usize {
        match self {
            Self::Soa { run, .. } => run.len(),
            Self::Spilled {
                spilled,
                partition,
                key,
            } => spilled
                .get(partition)
                .and_then(|inner| inner.get(key))
                .map_or(0, Vec::len),
        }
    }

    /// The value at run offset `off`. The caller ensures `off < len()`.
    fn get(&self, off: usize) -> &V {
        match self {
            Self::Soa { partition, run, .. } => partition.value_at(run.start + off),
            Self::Spilled {
                spilled,
                partition,
                key,
            } => &spilled
                .get(partition)
                .and_then(|inner| inner.get(key))
                .expect("active cursor must reference a present key")[off],
        }
    }

    /// Overwrite the value at run offset `off`. The caller ensures `off < len()`.
    fn set(&mut self, off: usize, value: V) {
        match self {
            Self::Soa { partition, run, .. } => partition.set(run.start + off, value),
            Self::Spilled {
                spilled,
                partition,
                key,
            } => {
                spilled
                    .get_mut(partition)
                    .and_then(|inner| inner.get_mut(key))
                    .expect("active cursor must reference a present key")[off] = value;
            }
        }
    }

    /// Insert `value` at run offset `off`, returning whether this created the key (its first value).
    fn insert(&mut self, off: usize, value: V) -> bool {
        match self {
            Self::Soa {
                partition,
                key,
                run,
            } => {
                #[allow(unstable_name_collisions)]
                let created = run.is_empty(); // empty run => key absent => this creates it
                partition.insert_at(run.start + off, *key, value);
                run.end += 1;
                created
            }
            Self::Spilled {
                spilled,
                partition,
                key,
            } => match spilled.entry(*partition).or_default().entry(*key) {
                btree_map::Entry::Occupied(mut run) => {
                    run.get_mut().insert(off, value);
                    false
                }
                btree_map::Entry::Vacant(run) => {
                    run.insert(vec![value]);
                    true
                }
            },
        }
    }

    /// Remove the value at run offset `off`, returning whether that emptied (and so removed) the key.
    fn remove(&mut self, off: usize) -> bool {
        match self {
            Self::Soa { partition, run, .. } => {
                partition.remove(run.start + off);
                run.end -= 1;
                #[allow(unstable_name_collisions)]
                run.is_empty()
            }
            Self::Spilled {
                spilled,
                partition,
                key,
            } => {
                let hash_map::Entry::Occupied(mut part) = spilled.entry(*partition) else {
                    unreachable!("active cursor must reference a present partition")
                };
                let btree_map::Entry::Occupied(mut run) = part.get_mut().entry(*key) else {
                    unreachable!("active cursor must reference a present key")
                };
                run.get_mut().remove(off);
                if !run.get().is_empty() {
                    return false;
                }
                // Removed the key's last value; drop the key, and de-spill the partition (back to an
                // empty sorted array) if that was its last key.
                run.remove();
                if part.get().is_empty() {
                    part.remove();
                }
                true
            }
        }
    }
}

/// A [crate::index::Cursor] over a single translated key's values.
///
/// Both representations -- the inline sorted array and the spilled `BTreeMap` -- share one
/// iteration protocol; see the module docs.
pub struct Cursor<'a, K: Ord + Copy, V> {
    backing: Backing<'a, K, V>,
    state: State,
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, K: Ord + Copy, V> Cursor<'a, K, V> {
    /// A cursor over a key's values held inline in a sorted-array partition. `run` is the (non-empty)
    /// index range of `key`'s values within the partition.
    pub(super) const fn soa(
        partition: &'a mut Partition<K, V>,
        key: K,
        run: Range<usize>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            backing: Backing::Soa {
                partition,
                key,
                run,
            },
            state: State::NeedNext { from: 0 },
            keys,
            items,
            pruned,
        }
    }

    /// A cursor over a key's values held in a spilled partition's `BTreeMap`.
    pub(super) const fn spilled(
        spilled: &'a mut HashMap<usize, BTreeMap<K, Vec<V>>>,
        partition: usize,
        key: K,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            backing: Backing::Spilled {
                spilled,
                partition,
                key,
            },
            state: State::NeedNext { from: 0 },
            keys,
            items,
            pruned,
        }
    }
}

impl<K: Ord + Copy + Send + Sync, V: Send + Sync> CursorTrait for Cursor<'_, K, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        let off = match self.state {
            State::Done => return None,
            State::NeedNext { from } => from,
            State::Active { offset } => offset + 1,
        };
        if off >= self.backing.len() {
            self.state = State::Done;
            return None;
        }
        self.state = State::Active { offset: off };
        Some(self.backing.get(off))
    }

    fn update(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => self.backing.set(offset, value),
        }
    }

    fn insert(&mut self, value: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Active { offset } => {
                // Place immediately after the current value (never a new key, so the return is
                // ignored); `next()` then returns the value after the inserted one, skipping both
                // the current and the inserted.
                self.backing.insert(offset + 1, value);
                self.items.inc();
                self.state = State::NeedNext { from: offset + 2 };
            }
            State::Done => {
                // Append at the oldest position (run end), re-creating the key if it was emptied.
                let end = self.backing.len();
                if self.backing.insert(end, value) {
                    self.keys.inc();
                }
                self.items.inc();
            }
        }
    }

    fn delete(&mut self) {
        let offset = match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { offset } => offset,
        };
        if self.backing.remove(offset) {
            // Removed the key's last value; the key is gone.
            self.keys.dec();
        }
        self.items.dec();
        self.pruned.inc();

        // The value after the deleted one shifted into `offset`.
        self.state = State::NeedNext { from: offset };
    }
}
