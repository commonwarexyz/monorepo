//! Shared structures and functionality for [crate::index] types.

use crate::index::Cursor as CursorTrait;
use commonware_runtime::telemetry::metrics::{Counter, Gauge};
use std::ptr::NonNull;

/// Each key is mapped to a [Record] that contains a linked list of potential values for that key.
///
/// We avoid using a [Vec] to store values because the common case (where there are no collisions)
/// would require an additional 24 bytes of memory for each value (the `len`, `capacity`, and `ptr`
/// fields).
///
/// Again optimizing for the common case, we store the first value directly in the [Record] to avoid
/// indirection (heap jumping).
pub struct Record<V: Send + Sync> {
    pub(super) value: V,
    pub(super) next: Option<Box<Self>>,
}

pub(super) fn insert_front<V: Send + Sync>(record: &mut Record<V>, value: V) {
    let old = std::mem::replace(&mut record.value, value);
    record.next = Some(Box::new(Record {
        value: old,
        next: record.next.take(),
    }));
}

pub trait IndexEntry<V: Send + Sync>: Send + Sync {
    fn get_mut(&mut self) -> &mut Record<V>;
    fn remove(self);
}

/// Panic message shown when `next()` is not called after [Cursor] creation or after `insert()` or
/// `delete()`.
const MUST_CALL_NEXT: &str = "must call Cursor::next()";

/// Panic message shown when `update()` or `delete()` is called after [Cursor] has returned `None`.
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Position of the [Cursor] within the linked list owned by its entry.
enum State<V: Send + Sync> {
    /// Before first `next()` call, or immediately after `insert()`/`delete()`.
    ///
    /// `from` is the node the next `next()` will step from; `None` means start at the entry head.
    NeedNext { from: Option<NonNull<Record<V>>> },
    /// `next()` returned `current`; `update()`/`delete()`/`insert()` are valid.
    ///
    /// `prev` is the predecessor live node, `None` when `current` is the entry head.
    Active {
        current: NonNull<Record<V>>,
        prev: Option<NonNull<Record<V>>>,
    },
    /// `next()` returned `None`; only `insert()` (which appends) is valid.
    ///
    /// `tail` is the final node of the chain, used by `insert` to append.
    Done { tail: NonNull<Record<V>> },
    /// The sole element was deleted; the entry will be removed on Drop.
    EntryRemoved,
}

// Manual `Copy`/`Clone` to avoid deriving an unnecessary `V: Copy` bound: the enum only contains
// `NonNull<Record<V>>` (always `Copy`) and `Option<NonNull<...>>` (also `Copy`).
impl<V: Send + Sync> Clone for State<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V: Send + Sync> Copy for State<V> {}

/// A cursor that traverses and mutates a linked list of [Record]s in place using raw pointers.
///
/// Invariants:
/// - `entry` owns the linked list and keeps it exclusively borrowed for the cursor's lifetime.
/// - All pointers stored inside `state` were created from exclusive references via `NonNull::from`
///   and refer to nodes owned by `entry`.
/// - In [`State::Active`], when `prev` is `Some`, `prev.next` owns the node at `current`.
/// - After a non-head delete, the [`State::NeedNext`] `from` is the surviving predecessor;
///   after a head delete, it is `None` so the next `next()` re-reads the entry head.
pub struct Cursor<'a, V: Send + Sync, E: IndexEntry<V>> {
    // The occupied index entry that owns the linked list while the cursor exists.
    entry: Option<E>,
    // The current position/state of the cursor, including any live pointers into the chain.
    state: State<V>,

    // Metrics.
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, V: Send + Sync, E: IndexEntry<V>> Cursor<'a, V, E> {
    /// Creates a new [Cursor] from an occupied index entry.
    pub(super) const fn new(
        entry: E,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            entry: Some(entry),
            state: State::NeedNext { from: None },
            keys,
            items,
            pruned,
        }
    }

    const fn record_mut(&mut self, mut ptr: NonNull<Record<V>>) -> &mut Record<V> {
        // SAFETY: `ptr` was created by `NonNull::from` from a record owned by `entry`, which is
        // exclusively borrowed through this cursor. Cursor state clears or rewinds pointers before
        // an owner is dropped.
        unsafe { ptr.as_mut() }
    }
}

impl<V: Send + Sync, E: IndexEntry<V>> CursorTrait for Cursor<'_, V, E> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        let from = match self.state {
            State::Done { .. } | State::EntryRemoved => return None,
            State::NeedNext { from } => from,
            State::Active { current, .. } => Some(current),
        };

        // Derive the next pointer from `from.next`, or the entry head when `from` is `None`.
        let next_ptr = if let Some(from) = from {
            match self.record_mut(from).next.as_deref_mut() {
                Some(next) => NonNull::from(next),
                None => {
                    self.state = State::Done { tail: from };
                    return None;
                }
            }
        } else {
            NonNull::from(self.entry.as_mut().unwrap().get_mut())
        };

        self.state = State::Active {
            current: next_ptr,
            prev: from,
        };
        Some(&self.record_mut(next_ptr).value)
    }

    fn update(&mut self, v: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done { .. } | State::EntryRemoved => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { current, .. } => {
                self.record_mut(current).value = v;
            }
        }
    }

    fn insert(&mut self, v: V) {
        match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Active { current, .. } => {
                self.items.inc();
                let inserted = {
                    let current_record = self.record_mut(current);
                    let new = Box::new(Record {
                        value: v,
                        next: current_record.next.take(),
                    });
                    current_record.next = Some(new);
                    NonNull::from(current_record.next.as_deref_mut().unwrap())
                };
                // Advance past the inserted node so next() returns the element after it.
                self.state = State::NeedNext {
                    from: Some(inserted),
                };
            }
            State::EntryRemoved => {
                // Re-populate the entry that was emptied by delete.
                self.items.inc();
                let entry_record = self.entry.as_mut().unwrap().get_mut();
                entry_record.value = v;
                entry_record.next = None;
                self.state = State::Done {
                    tail: NonNull::from(entry_record),
                };
            }
            State::Done { tail } => {
                self.items.inc();
                let inserted = {
                    let tail_record = self.record_mut(tail);
                    tail_record.next = Some(Box::new(Record {
                        value: v,
                        next: None,
                    }));
                    NonNull::from(tail_record.next.as_deref_mut().unwrap())
                };
                self.state = State::Done { tail: inserted };
            }
        }
    }

    fn delete(&mut self) {
        let (current, prev) = match self.state {
            State::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            State::Done { .. } | State::EntryRemoved => panic!("{NO_ACTIVE_ITEM}"),
            State::Active { current, prev } => (current, prev),
        };
        self.pruned.inc();
        self.items.dec();

        if let Some(prev) = prev {
            // Deleting a non-head node: relink prev.next to current.next.
            let next = self.record_mut(current).next.take();
            self.record_mut(prev).next = next;
            self.state = State::NeedNext { from: Some(prev) };
        } else {
            // Deleting the head node (the entry record itself).
            let head = self.record_mut(current);
            if let Some(next) = head.next.take() {
                // Promote the next record into the head position.
                head.value = next.value;
                head.next = next.next;
                self.state = State::NeedNext { from: None };
            } else {
                // Sole element deleted.
                self.state = State::EntryRemoved;
            }
        }
    }
}

// SAFETY: `NonNull` is not `Send`, so this cannot be derived automatically. The pointers stored
// inside `state` are only bookkeeping pointers into the linked list owned by `entry`. Moving the
// cursor to another thread also moves `entry`, keeping the list alive and exclusively borrowed by
// the cursor.
unsafe impl<V: Send + Sync, E: IndexEntry<V>> Send for Cursor<'_, V, E> {}
// SAFETY: `NonNull` is not `Sync`, so this cannot be derived automatically. Sharing a cursor does
// not grant access to the records without `&mut self`, and `entry` keeps the list alive and
// exclusively borrowed for the cursor's lifetime.
unsafe impl<V: Send + Sync, E: IndexEntry<V>> Sync for Cursor<'_, V, E> {}

impl<V: Send + Sync, E: IndexEntry<V>> Drop for Cursor<'_, V, E> {
    fn drop(&mut self) {
        if matches!(self.state, State::EntryRemoved) {
            self.keys.dec();
            self.entry.take().unwrap().remove();
        }
    }
}

/// Walks the linked list of values starting at `head` and yields each value.
pub(super) fn iter_chain<V: Send + Sync>(head: &Record<V>) -> impl Iterator<Item = &V> + Send {
    std::iter::successors(Some(head), |r| r.next.as_deref()).map(|r| &r.value)
}
