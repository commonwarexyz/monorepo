//! Shared structures and functionality for [crate::index] types.

use crate::index::Cursor as CursorTrait;
use commonware_runtime::telemetry::metrics::{Counter, Gauge};

/// Panic message shown when `next()` is not called after cursor creation or after `insert()` or
/// `delete()`.
const MUST_CALL_NEXT: &str = "must call Cursor::next()";

/// Panic message shown when `update()` or `delete()` is called after a cursor has returned `None`.
const NO_ACTIVE_ITEM: &str = "no active item in Cursor";

/// Position of a cursor within a newest-first run.
enum RunState {
    /// Before first `next()` call, or immediately after `insert()`/`delete()`.
    ///
    /// `from` is the run offset the next `next()` will try.
    NeedNext { from: usize },
    /// `next()` returned the value at `offset`; `update()`/`delete()`/`insert()` are valid.
    Active { offset: usize },
    /// `next()` returned `None`; only `insert()` (which appends) is valid.
    Done,
}

/// A cursor over a mutable newest-first value run.
pub struct RunCursor<'a, V> {
    run: &'a mut Vec<V>,
    state: RunState,
    keys: Gauge,
    items: Gauge,
    pruned: Counter,
}

impl<'a, V> RunCursor<'a, V> {
    pub(super) const fn new(
        run: &'a mut Vec<V>,
        keys: Gauge,
        items: Gauge,
        pruned: Counter,
    ) -> Self {
        Self {
            run,
            state: RunState::NeedNext { from: 0 },
            keys,
            items,
            pruned,
        }
    }
}

impl<V: Send + Sync> CursorTrait for RunCursor<'_, V> {
    type Value = V;

    fn next(&mut self) -> Option<&V> {
        let off = match self.state {
            RunState::Done => return None,
            RunState::NeedNext { from } => from,
            RunState::Active { offset } => offset + 1,
        };
        if off >= self.run.len() {
            self.state = RunState::Done;
            return None;
        }
        self.state = RunState::Active { offset: off };
        Some(&self.run[off])
    }

    fn update(&mut self, value: V) {
        match self.state {
            RunState::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            RunState::Done => panic!("{NO_ACTIVE_ITEM}"),
            RunState::Active { offset } => self.run[offset] = value,
        }
    }

    fn insert(&mut self, value: V) {
        match self.state {
            RunState::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            RunState::Active { offset } => {
                // Place immediately after the current value; `next()` then skips the inserted value.
                self.run.insert(offset + 1, value);
                self.items.inc();
                self.state = RunState::NeedNext { from: offset + 2 };
            }
            RunState::Done => {
                // Append at the oldest position, re-creating the key if it was emptied.
                if self.run.is_empty() {
                    self.keys.inc();
                }
                self.run.push(value);
                self.items.inc();
            }
        }
    }

    fn delete(&mut self) {
        let offset = match self.state {
            RunState::NeedNext { .. } => panic!("{MUST_CALL_NEXT}"),
            RunState::Done => panic!("{NO_ACTIVE_ITEM}"),
            RunState::Active { offset } => offset,
        };
        self.run.remove(offset);
        if self.run.is_empty() {
            // Removed the key's last visible value.
            self.keys.dec();
        }
        self.items.dec();
        self.pruned.inc();
        // The value after the deleted one shifted into `offset`.
        self.state = RunState::NeedNext { from: offset };
    }
}
