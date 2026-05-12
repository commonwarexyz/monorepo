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
#[derive(PartialEq, Eq)]
pub(super) struct Record<V: Eq + Send + Sync> {
    pub(super) value: V,
    pub(super) next: Option<Box<Self>>,
}

pub(super) fn insert_front<V: Eq + Send + Sync>(record: &mut Record<V>, mut value: V) {
    std::mem::swap(&mut record.value, &mut value);
    record.next = Some(Box::new(Record {
        value,
        next: record.next.take(),
    }));
}

pub(super) trait IndexEntry<V: Eq + Send + Sync>: Send + Sync {
    fn get_mut(&mut self) -> &mut Record<V>;
    fn remove(self);
}

/// Panic message shown when `next()` is not called after [Cursor] creation or after `insert()` or
/// `delete()`.
const MUST_CALL_NEXT: &str = "must call Cursor::next()";

/// Panic message shown when `update()` or `delete()` is called after [Cursor] has returned `None`.
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

#[derive(PartialEq, Eq)]
enum State {
    /// Before first `next()` call, or immediately after `insert()`/`delete()`.
    NeedNext,
    /// `next()` returned a value; `update()`/`delete()` are valid.
    Active,
    /// `next()` returned `None`; only `insert()` is valid.
    Done,
    /// The sole element was deleted; the entry will be removed on Drop.
    EntryRemoved,
}

/// A cursor that traverses and mutates a linked list of [Record]s in place using raw pointers.
///
/// Tracks `prev` (for relinking on delete) and `current` (last item returned by `next`).
/// The next element to visit is derived from `current.next` (or the entry head when
/// `current` is `None`), so no separate `upcoming` pointer is needed.
///
/// Invariants:
/// - `entry` owns the linked list and keeps it exclusively borrowed for the cursor's lifetime.
/// - `prev` and `current`, when present, point into that list.
/// - `prev` and `current` are created only from exclusive references through `record_ptr`.
/// - When both are present, `prev.next` owns `current`.
/// - After deleting a node, `current` is moved back to the previous live node or cleared.
pub(super) struct Cursor<'a, V: Eq + Send + Sync, E: IndexEntry<V>> {
    // The occupied index entry that owns the linked list while the cursor exists.
    entry: Option<E>,
    // The live record immediately before `current`, used to relink on non-head deletes.
    prev: Option<NonNull<Record<V>>>,
    // The last record returned by `next()`.
    current: Option<NonNull<Record<V>>>,
    // The current position/state of the cursor.
    state: State,

    // Metrics.
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, V: Eq + Send + Sync, E: IndexEntry<V>> Cursor<'a, V, E> {
    /// Creates a new [Cursor] from an occupied index entry.
    pub(super) const fn new(
        entry: E,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            entry: Some(entry),
            prev: None,
            current: None,
            state: State::NeedNext,
            keys,
            items,
            pruned,
        }
    }

    fn record_ptr(record: &mut Record<V>) -> NonNull<Record<V>> {
        NonNull::from(record)
    }

    const fn record_mut(&mut self, mut ptr: NonNull<Record<V>>) -> &mut Record<V> {
        // SAFETY: `ptr` was created by `record_ptr` from a record owned by `entry`, which is
        // exclusively borrowed through this cursor. Cursor state clears or rewinds pointers before
        // an owner is dropped.
        unsafe { ptr.as_mut() }
    }
}

impl<V: Eq + Send + Sync, E: IndexEntry<V>> CursorTrait for Cursor<'_, V, E> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        match self.state {
            State::Done | State::EntryRemoved => return None,
            State::NeedNext | State::Active => {}
        }

        // Derive the next record from `current.next` or the entry head.
        let next_ptr = if let Some(current) = self.current {
            match self.record_mut(current).next.as_deref_mut() {
                Some(next) => Self::record_ptr(next),
                None => {
                    self.state = State::Done;
                    return None;
                }
            }
        } else {
            Self::record_ptr(self.entry.as_mut().unwrap().get_mut())
        };

        self.prev = self.current;
        self.current = Some(next_ptr);
        self.state = State::Active;
        Some(&self.record_mut(next_ptr).value)
    }

    fn update(&mut self, v: V) {
        match self.state {
            State::NeedNext => panic!("{MUST_CALL_NEXT}"),
            State::Done | State::EntryRemoved => panic!("{NO_ACTIVE_ITEM}"),
            State::Active => {}
        }
        assert!(self.current.is_some(), "Active state requires current");
        let current = self.current.unwrap();
        self.record_mut(current).value = v;
    }

    fn insert(&mut self, v: V) {
        match self.state {
            State::NeedNext => panic!("{MUST_CALL_NEXT}"),
            State::Active => {
                self.items.inc();
                assert!(self.current.is_some(), "Active state requires current");
                let current = self.current.unwrap();
                let inserted = {
                    let current_record = self.record_mut(current);
                    let new = Box::new(Record {
                        value: v,
                        next: current_record.next.take(),
                    });
                    current_record.next = Some(new);
                    Self::record_ptr(current_record.next.as_deref_mut().unwrap())
                };
                // Advance past the inserted node so next() returns the element after it.
                self.prev = self.current;
                self.current = Some(inserted);
                self.state = State::NeedNext;
            }
            State::EntryRemoved => {
                // Re-populate the entry that was emptied by delete.
                self.items.inc();
                let entry_record = self.entry.as_mut().unwrap().get_mut();
                entry_record.value = v;
                entry_record.next = None;
                self.prev = None;
                self.current = Some(Self::record_ptr(entry_record));
                self.state = State::Done;
            }
            State::Done => {
                self.items.inc();
                let last = self.current.or(self.prev);
                assert!(last.is_some(), "Done state requires current or prev");
                let inserted = {
                    let last_record = self.record_mut(last.unwrap());
                    last_record.next = Some(Box::new(Record {
                        value: v,
                        next: None,
                    }));
                    Self::record_ptr(last_record.next.as_deref_mut().unwrap())
                };
                self.prev = last;
                self.current = Some(inserted);
                self.state = State::Done;
            }
        }
    }

    fn delete(&mut self) {
        match self.state {
            State::NeedNext => panic!("{MUST_CALL_NEXT}"),
            State::Done | State::EntryRemoved => panic!("{NO_ACTIVE_ITEM}"),
            State::Active => {}
        }
        self.pruned.inc();
        self.items.dec();

        assert!(self.current.is_some(), "Active state requires current");
        let current = self.current.unwrap();

        if let Some(prev) = self.prev {
            // Deleting a non-head node: relink prev.next to current.next.
            let next = self.record_mut(current).next.take();
            self.record_mut(prev).next = next;
            self.current = self.prev;
            self.prev = None;
            self.state = State::NeedNext;
        } else {
            // Deleting the head node (the entry record itself).
            let head = self.record_mut(current);
            if let Some(next) = head.next.take() {
                // Promote the next record into the head position.
                head.value = next.value;
                head.next = next.next;
                self.current = None;
                self.state = State::NeedNext;
            } else {
                // Sole element deleted.
                self.current = None;
                self.state = State::EntryRemoved;
            }
        }
    }

    /// Removes anything in the cursor that satisfies the predicate.
    fn prune(&mut self, predicate: &impl Fn(&V) -> bool) {
        while let Some(old) = self.next() {
            if predicate(old) {
                self.delete();
            }
        }
    }
}

// SAFETY: `NonNull` is not `Send`, so this cannot be derived automatically. `prev` and `current`
// are only bookkeeping pointers into the linked list owned by `entry`. Moving the cursor to another
// thread also moves `entry`, keeping the list alive and exclusively borrowed by the cursor.
unsafe impl<V: Eq + Send + Sync, E: IndexEntry<V>> Send for Cursor<'_, V, E> {}
// SAFETY: `NonNull` is not `Sync`, so this cannot be derived automatically. Sharing a cursor does
// not grant access to the records without `&mut self`, and `entry` keeps the list alive and
// exclusively borrowed for the cursor's lifetime.
unsafe impl<V: Eq + Send + Sync, E: IndexEntry<V>> Sync for Cursor<'_, V, E> {}

impl<V: Eq + Send + Sync, E: IndexEntry<V>> Drop for Cursor<'_, V, E> {
    fn drop(&mut self) {
        if self.state == State::EntryRemoved {
            self.keys.dec();
            self.entry.take().unwrap().remove();
        }
    }
}

/// An immutable iterator over the values associated with a translated key.
pub struct ImmutableCursor<'a, V: Eq + Send + Sync> {
    current: Option<&'a Record<V>>,
}

impl<'a, V: Eq + Send + Sync> ImmutableCursor<'a, V> {
    /// Creates a new [ImmutableCursor] from a [Record].
    pub(super) const fn new(record: &'a Record<V>) -> Self {
        Self {
            current: Some(record),
        }
    }
}

impl<'a, V: Eq + Send + Sync> Iterator for ImmutableCursor<'a, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        self.current.map(|record| {
            let value = &record.value;
            self.current = record.next.as_deref();
            value
        })
    }
}
