//! Shared structures and functionality for [crate::index] types.

use crate::index::Cursor as CursorTrait;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Each key is mapped to a [Record] that contains a linked list of potential values for that key.
///
/// We avoid using a [Vec] to store values because the common case (where there are no collisions)
/// would require an additional 24 bytes of memory for each value (the `len`, `capacity`, and `ptr`
/// fields).
///
/// Again optimizing for the common case, we store the first value directly in the [Record] to avoid
/// indirection (heap jumping).
#[derive(PartialEq, Eq)]
pub(super) struct Record<V: Eq> {
    pub(super) value: V,
    pub(super) next: Option<Box<Self>>,
}

pub(super) trait IndexEntry<V: Eq> {
    fn get(&self) -> &V;
    fn get_mut(&mut self) -> &mut Record<V>;
    fn remove(self);
}

/// Panic message shown when `next()` is not called after [Cursor] creation or after `insert()` or
/// `delete()`.
const MUST_CALL_NEXT: &str = "must call Cursor::next()";

/// Panic message shown when `update()` is called after [Cursor] has returned `None` or after
/// `insert()` or `delete()` (but before `next()`).
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Phases of the [Cursor] during iteration.
#[derive(PartialEq, Eq)]
enum Phase<V: Eq> {
    /// Before iteration starts.
    Initial,

    /// The current entry.
    Entry,
    /// Some item after the current entry.
    Next(Box<Record<V>>),

    /// Iteration is done.
    Done,
    /// The current entry has no valid item.
    EntryDeleted,

    /// The current entry has been deleted and we've updated its value in-place
    /// to be the value of the next record.
    PostDeleteEntry,
    /// The item has been deleted and we may be pointing to the next item.
    PostDeleteNext(Option<Box<Record<V>>>),
    /// An item has been inserted.
    PostInsert(Box<Record<V>>),
}

/// A cursor for [crate::index] types that can be instantiated with any [IndexEntry] implementation.
pub(super) struct Cursor<'a, V: Eq, E: IndexEntry<V>> {
    // The current phase of the cursor.
    phase: Phase<V>,

    // The current entry.
    entry: Option<E>,

    // The head of the linked list of previously visited records.
    past: Option<Box<Record<V>>>,
    // The tail of the linked list of previously visited records.
    past_tail: Option<*mut Record<V>>,
    // Whether we've pushed a record with a populated `next` field to `past` (invalidates
    // `past_tail`).
    past_pushed_list: bool,

    // Metrics.
    keys: &'a Gauge,
    items: &'a Gauge,
    pruned: &'a Counter,
}

impl<'a, V: Eq, E: IndexEntry<V>> Cursor<'a, V, E> {
    /// Creates a new [Cursor] from a mutable record reference, detaching its `next` chain for
    /// iteration.
    pub(super) const fn new(
        entry: E,
        keys: &'a Gauge,
        items: &'a Gauge,
        pruned: &'a Counter,
    ) -> Self {
        Self {
            phase: Phase::Initial,

            entry: Some(entry),

            past: None,
            past_tail: None,
            past_pushed_list: false,

            keys,
            items,
            pruned,
        }
    }

    /// Pushes a [Record] to the end of `past`.
    ///
    /// If the record has a `next`, this function cannot be called again.
    pub(super) fn past_push(&mut self, next: Box<Record<V>>) {
        // Ensure we only push a list once (`past_tail` becomes stale).
        assert!(!self.past_pushed_list);
        self.past_pushed_list = next.next.is_some();

        // Add `next` to the tail of `past`.
        if self.past_tail.is_none() {
            self.past = Some(next);
            self.past_tail = self.past.as_mut().map(|b| &mut **b as *mut Record<V>);
        } else {
            // SAFETY: `past_tail` is always either `None` or points to a valid `Record`
            // within the `self.past` linked list. We only enter this branch when `past_tail`
            // is `Some`, meaning it was previously set to point to an owned node. The
            // assertion verifies the invariant that `past_tail.next` is `None` before we
            // append to it.
            unsafe {
                assert!((*self.past_tail.unwrap()).next.is_none());
                (*self.past_tail.unwrap()).next = Some(next);
                let tail_next = (*self.past_tail.unwrap()).next.as_mut().unwrap();
                self.past_tail = Some(&mut **tail_next as *mut Record<V>);
            }
        }
    }

    /// If we are in a phase where we could return a value, return it.
    pub(super) fn value(&self) -> Option<&V> {
        match &self.phase {
            Phase::Initial => unreachable!(),
            Phase::Entry => self.entry.as_ref().map(|e| e.get()),
            Phase::Next(current) => Some(&current.value),
            Phase::Done | Phase::EntryDeleted => None,
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) | Phase::PostInsert(_) => {
                unreachable!()
            }
        }
    }
}

impl<V: Eq, E: IndexEntry<V>> CursorTrait for Cursor<'_, V, E> {
    type Value = V;

    fn update(&mut self, v: V) {
        match &mut self.phase {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                self.entry.as_mut().unwrap().get_mut().value = v;
            }
            Phase::Next(next) => {
                next.value = v;
            }
            Phase::Done
            | Phase::EntryDeleted
            | Phase::PostDeleteEntry
            | Phase::PostDeleteNext(_)
            | Phase::PostInsert(_) => unreachable!("{NO_ACTIVE_ITEM}"),
        }
    }

    fn next(&mut self) -> Option<&V> {
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial | Phase::PostDeleteEntry => {
                // We must start with some entry, so this will always be some non-None value.
                self.phase = Phase::Entry;
            }
            Phase::Entry => {
                // If there is a record after, we set it to be the current record.
                if let Some(next) = self.entry.as_mut().unwrap().get_mut().next.take() {
                    self.phase = Phase::Next(next);
                }
            }
            Phase::Next(mut current) | Phase::PostInsert(mut current) => {
                // Take the next record and push the current one to the past list.
                let next = current.next.take();
                self.past_push(current);

                // Set the next record to be the current record.
                if let Some(next) = next {
                    self.phase = Phase::Next(next);
                }
            }
            Phase::Done => {}
            Phase::EntryDeleted => {
                self.phase = Phase::EntryDeleted;
            }
            Phase::PostDeleteNext(current) => {
                // If the stale value is some, we set it to be the current record.
                if let Some(current) = current {
                    self.phase = Phase::Next(current);
                }
            }
        }
        self.value()
    }

    fn insert(&mut self, v: V) {
        self.items.inc();
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                // Create a new record that points to entry's next.
                let new = Box::new(Record {
                    value: v,
                    next: self.entry.as_mut().unwrap().get_mut().next.take(),
                });

                // Set the phase to the new record.
                self.phase = Phase::PostInsert(new);
            }
            Phase::Next(mut current) => {
                // Take next.
                let next = current.next.take();

                // Add current to the past list.
                self.past_push(current);

                // Create a new record that points to the next's next.
                let new = Box::new(Record { value: v, next });
                self.phase = Phase::PostInsert(new);
            }
            Phase::Done => {
                // If we are done, we need to create a new record and
                // immediately push it to the past list.
                let new = Box::new(Record {
                    value: v,
                    next: None,
                });
                self.past_push(new);
            }
            Phase::EntryDeleted => {
                // If entry is deleted, we need to update it.
                self.entry.as_mut().unwrap().get_mut().value = v;

                // We don't consider overwriting a deleted entry a collision.
            }
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) | Phase::PostInsert(_) => {
                unreachable!("{MUST_CALL_NEXT}")
            }
        }
    }

    fn delete(&mut self) {
        self.pruned.inc();
        self.items.dec();
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial => unreachable!("{MUST_CALL_NEXT}"),
            Phase::Entry => {
                // Attempt to overwrite the entry with the next value.
                let entry = self.entry.as_mut().unwrap().get_mut();
                if let Some(next) = entry.next.take() {
                    entry.value = next.value;
                    entry.next = next.next;
                    self.phase = Phase::PostDeleteEntry;
                    return;
                }

                // If there is no next, we consider the entry deleted.
                self.phase = Phase::EntryDeleted;
                // We wait to update metrics until `drop()`.
            }
            Phase::Next(mut current) => {
                // Drop current instead of pushing it to the past list.
                let next = current.next.take();
                self.phase = Phase::PostDeleteNext(next);
            }
            Phase::Done | Phase::EntryDeleted => unreachable!("{NO_ACTIVE_ITEM}"),
            Phase::PostDeleteEntry | Phase::PostDeleteNext(_) | Phase::PostInsert(_) => {
                unreachable!("{MUST_CALL_NEXT}")
            }
        }
    }

    /// Removes anything in the cursor that satisfies the predicate.
    fn prune(&mut self, predicate: &impl Fn(&V) -> bool) {
        loop {
            let Some(old) = self.next() else {
                break;
            };
            if predicate(old) {
                self.delete();
            }
        }
    }
}

// SAFETY: [Send] is safe because the raw pointer `past_tail` only ever points to heap memory
// owned by `self.past`. Since the pointer's referent is moved along with the [Cursor], no data
// races can occur. The `where` clause ensures all generic parameters are also [Send].
unsafe impl<'a, V, E> Send for Cursor<'a, V, E>
where
    V: Eq + Send,
    E: IndexEntry<V> + Send,
{
}

impl<V: Eq, E: IndexEntry<V>> Drop for Cursor<'_, V, E> {
    fn drop(&mut self) {
        // Take the entry.
        let mut entry = self.entry.take().unwrap();

        // If there is a dangling next, we should add it to past.
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Initial | Phase::Entry => {
                // No action needed.
            }
            Phase::Next(next) => {
                // If there is a next, we should add it to past.
                self.past_push(next);
            }
            Phase::Done => {
                // No action needed.
            }
            Phase::EntryDeleted => {
                // If the entry is deleted, we should remove it.
                self.keys.dec();
                entry.remove();
                return;
            }
            Phase::PostDeleteEntry => {
                // No action needed.
            }
            Phase::PostDeleteNext(Some(next)) => {
                // If there is a stale record, we should add it to past.
                self.past_push(next);
            }
            Phase::PostDeleteNext(None) => {
                // No action needed.
            }
            Phase::PostInsert(next) => {
                // If there is a current record, we should add it to past.
                self.past_push(next);
            }
        }

        // Attach the tip of past to the entry.
        if let Some(past) = self.past.take() {
            entry.get_mut().next = Some(past);
        }
    }
}

/// An immutable iterator over the values associated with a translated key.
pub(super) struct ImmutableCursor<'a, V: Eq> {
    current: Option<&'a Record<V>>,
}

impl<'a, V: Eq> ImmutableCursor<'a, V> {
    /// Creates a new [ImmutableCursor] from a [Record].
    pub(super) const fn new(record: &'a Record<V>) -> Self {
        Self {
            current: Some(record),
        }
    }
}

impl<'a, V: Eq> Iterator for ImmutableCursor<'a, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        self.current.map(|record| {
            let value = &record.value;
            self.current = record.next.as_deref();
            value
        })
    }
}
