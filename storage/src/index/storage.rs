//! Shared structures and functionality for [crate::index] types.

use crate::index::Cursor as CursorTrait;
use commonware_runtime::telemetry::metrics::{Counter, Gauge};
use std::collections::BTreeMap;

/// Maps a translated key to the values that conflict with the value stored inline in the index's
/// map, stored oldest first.
///
/// In the common case (no collisions), a translated key maps to exactly one value, which is stored
/// directly in the index's map. Storing conflicting values out-of-line keeps map entries as small
/// as possible: a per-entry chain pointer or [Vec] would add 8+ bytes to every entry to support
/// collisions that are rare for well-distributed translated keys.
///
/// The logical chain of values for a key is the inline map value followed by the overflow values
/// in reverse order (newest first).
pub type Overflow<K, V> = BTreeMap<K, Vec<V>>;

/// Adds a value displaced from a key's inline slot to that key's overflow chain.
///
/// Collisions are rare for well-distributed translated keys, so this is kept out of line to
/// keep the hot (vacant or collision-free) insert path small.
#[cold]
#[inline(never)]
pub(super) fn push_displaced<K: Ord + Copy, V>(overflow: &mut Overflow<K, V>, key: K, old: V) {
    overflow.entry(key).or_default().push(old);
}

/// Identifies one value in the chain of values associated with a translated key.
#[derive(Clone, Copy)]
enum Position {
    /// The value stored inline in the index's map.
    Head,
    /// The value at this index of the key's overflow vector. Iteration visits overflow values
    /// from the highest index down to 0.
    Overflow(usize),
}

pub trait IndexEntry<V: Send + Sync>: Send + Sync {
    fn get_mut(&mut self) -> &mut V;
    fn remove(self);
}

/// Panic message shown when `next()` is not called after [Cursor] creation or after `insert()` or
/// `delete()`.
const MUST_CALL_NEXT: &str = "must call Cursor::next()";

/// Panic message shown when `update()` or `delete()` is called after [Cursor] has returned `None`.
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Position of the [Cursor] within the chain of values owned by its entry.
#[derive(Clone, Copy)]
enum State {
    /// Before first `next()` call, or immediately after `insert()`/`delete()`.
    ///
    /// `from` is the position the next `next()` will step from; `None` means start at the head.
    NeedNext { from: Option<Position> },
    /// `next()` returned the value at `pos`; `update()`/`delete()`/`insert()` are valid.
    Active { pos: Position },
    /// `next()` returned `None`; only `insert()` (which appends) is valid.
    Done,
    /// The sole element was deleted; the entry will be removed on Drop.
    EntryRemoved,
}

/// A cursor that traverses and mutates the chain of values associated with a translated key: the
/// entry's inline value followed by the key's overflow values in reverse order.
///
/// The first cursor operation that needs the key's overflow values removes them from the overflow
/// map and operates on them directly, avoiding a map probe per operation. Any remaining values
/// are reinstalled when the cursor is dropped. Operations that never advance past the inline
/// value (e.g. find-then-update) never touch the overflow map.
///
/// Invariants:
/// - `entry` holds the inline value and keeps it exclusively borrowed for the cursor's lifetime.
/// - Any [`Position::Overflow`] index stored in `state` is within bounds of the taken `chain`
///   (a position past the head is only reachable after the chain is taken; [`State::NeedNext`]
///   may hold the index of a just-deleted slot, which is only ever stepped down from, never
///   read).
/// - [`State::EntryRemoved`] implies the chain was taken and is empty.
pub struct Cursor<'a, K: Ord + Copy, V: Send + Sync, E: IndexEntry<V>> {
    // The occupied index entry holding the inline value while the cursor exists.
    entry: Option<E>,
    // The translated key whose values the cursor traverses.
    key: K,
    // The overflow values for all keys in the index, used to take and reinstall `chain`.
    overflow: &'a mut Overflow<K, V>,
    // The key's overflow values; `None` until first needed.
    chain: Option<Vec<V>>,
    // The current position/state of the cursor.
    state: State,

    // Metrics.
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, K: Ord + Copy, V: Send + Sync, E: IndexEntry<V>> Cursor<'a, K, V, E> {
    /// Creates a new [Cursor] from an occupied index entry.
    #[inline]
    pub(super) const fn new(
        entry: E,
        key: K,
        overflow: &'a mut Overflow<K, V>,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            entry: Some(entry),
            key,
            overflow,
            chain: None,
            state: State::NeedNext { from: None },
            keys,
            items,
            pruned,
        }
    }

    #[inline]
    fn head_mut(&mut self) -> &mut V {
        self.entry.as_mut().unwrap().get_mut()
    }

    /// Returns the key's overflow chain, taking it from the overflow map on first use.
    fn chain_mut(&mut self) -> &mut Vec<V> {
        let key = self.key;
        let overflow = &mut self.overflow;
        self.chain.get_or_insert_with(|| {
            if overflow.is_empty() {
                Vec::new()
            } else {
                overflow.remove(&key).unwrap_or_default()
            }
        })
    }
}

impl<K: Ord + Copy + Send + Sync, V: Send + Sync, E: IndexEntry<V>> CursorTrait
    for Cursor<'_, K, V, E>
{
    type Value = V;

    #[inline]
    fn next(&mut self) -> Option<&V> {
        let from = match self.state {
            State::Done | State::EntryRemoved => return None,
            State::NeedNext { from } => from,
            State::Active { pos } => Some(pos),
        };

        // Derive the next position from `from`, or start at the head when `from` is `None`.
        let next = match from {
            None => Position::Head,
            Some(Position::Head) => match self.chain_mut().len() {
                0 => {
                    self.state = State::Done;
                    return None;
                }
                len => Position::Overflow(len - 1),
            },
            Some(Position::Overflow(0)) => {
                self.state = State::Done;
                return None;
            }
            Some(Position::Overflow(i)) => Position::Overflow(i - 1),
        };

        self.state = State::Active { pos: next };
        Some(match next {
            Position::Head => self.head_mut(),
            Position::Overflow(i) => &self.chain.as_ref().unwrap()[i],
        })
    }

    #[inline]
    fn update(&mut self, v: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done | State::EntryRemoved => panic!("{NO_ACTIVE_ITEM}"),
            State::Active {
                pos: Position::Head,
            } => *self.head_mut() = v,
            State::Active {
                pos: Position::Overflow(i),
            } => self.chain.as_mut().unwrap()[i] = v,
        }
    }

    fn insert(&mut self, v: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Active { pos } => {
                self.items.inc();
                // Insert immediately after the current position in iteration order. Iteration
                // visits overflow values from the highest index down, so the slot after the head
                // is the end of the vector, and the slot after `Overflow(i)` is index `i` (which
                // shifts the current value up by one).
                let chain = self.chain_mut();
                let at = match pos {
                    Position::Head => chain.len(),
                    Position::Overflow(i) => i,
                };
                chain.insert(at, v);
                // Step from the inserted value so next() returns the element after it.
                self.state = State::NeedNext {
                    from: Some(Position::Overflow(at)),
                };
            }
            State::EntryRemoved => {
                // Re-populate the entry that was emptied by delete.
                self.items.inc();
                *self.head_mut() = v;
                self.state = State::Done;
            }
            State::Done => {
                // Append to the end of the iteration order (index 0 of the overflow vector).
                self.items.inc();
                self.chain_mut().insert(0, v);
            }
        }
    }

    fn delete(&mut self) {
        let pos = match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done | State::EntryRemoved => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { pos } => pos,
        };
        self.pruned.inc();
        self.items.dec();

        match pos {
            Position::Head => {
                if let Some(promoted) = self.chain_mut().pop() {
                    // Promote the newest overflow value (the next value in iteration order) into
                    // the head position, so the following next() revisits the head.
                    *self.head_mut() = promoted;
                    self.state = State::NeedNext { from: None };
                } else {
                    // Sole element deleted.
                    self.state = State::EntryRemoved;
                }
            }
            Position::Overflow(i) => {
                self.chain.as_mut().unwrap().remove(i);
                // Step from the deleted slot so next() returns the element after it.
                self.state = State::NeedNext {
                    from: Some(Position::Overflow(i)),
                };
            }
        }
    }
}

impl<K: Ord + Copy, V: Send + Sync, E: IndexEntry<V>> Drop for Cursor<'_, K, V, E> {
    #[inline]
    fn drop(&mut self) {
        if matches!(self.state, State::EntryRemoved) {
            self.keys.dec();
            self.entry.take().unwrap().remove();
        } else if let Some(chain) = self.chain.take() {
            // Reinstall the key's remaining overflow values.
            if !chain.is_empty() {
                self.overflow.insert(self.key, chain);
            }
        }
    }
}

/// Iterates over all values associated with a translated key, newest first: the inline head
/// value, then any overflow values in reverse insertion order.
///
/// The overflow map is probed lazily, only when iteration advances past the head value. Callers
/// that consume just the first value (e.g. existence checks) never touch the overflow map.
pub struct Values<'a, K: Ord, V> {
    head: Option<&'a V>,
    overflow: OverflowValues<'a, K, V>,
}

/// The overflow portion of a [Values] iterator.
enum OverflowValues<'a, K: Ord, V> {
    /// The overflow map has not been probed yet.
    Pending {
        overflow: &'a Overflow<K, V>,
        key: K,
    },
    /// Iterating the key's overflow values (an empty iterator when the key has none).
    Iter(std::iter::Rev<std::slice::Iter<'a, V>>),
}

impl<'a, K: Ord, V> Values<'a, K, V> {
    /// Creates a [Values] iterator from a key's optional inline value and the index's overflow
    /// map. If `head` is `None` (the key is absent), the iterator is empty and the overflow map
    /// is never probed.
    pub(super) fn new(head: Option<&'a V>, overflow: &'a Overflow<K, V>, key: K) -> Self {
        let overflow = match head {
            Some(_) => OverflowValues::Pending { overflow, key },
            None => OverflowValues::Iter([].iter().rev()),
        };
        Self { head, overflow }
    }
}

impl<'a, K: Ord, V> Iterator for Values<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<&'a V> {
        if let Some(head) = self.head.take() {
            return Some(head);
        }
        loop {
            match &mut self.overflow {
                OverflowValues::Pending { overflow, key } => {
                    let values = overflow.get(key).map_or(&[][..], Vec::as_slice);
                    self.overflow = OverflowValues::Iter(values.iter().rev());
                }
                OverflowValues::Iter(values) => return values.next(),
            }
        }
    }
}
