//! Run-scoped counts of the honest events a fuzz configuration exists to reach:
//! handoff decisions an application took, votes at term starts on uncertified
//! parents, term-start children notarized over a single-certifier parent.
//!
//! The counts never gate a fuzz run. Smoke tests read them after a fixed input,
//! so a configuration that never arms what it samples fails there instead of
//! passing vacuously. They are kept apart from [`crate::byzantine`], whose
//! totals an honest run must keep at zero.
//!
//! The counts are thread-local, as the Byzantine ones are: the deterministic
//! runtime executes every task inline on the thread that started it.

use std::{cell::RefCell, collections::BTreeMap};

thread_local! {
    static COUNTS: RefCell<BTreeMap<&'static str, u64>> = const { RefCell::new(BTreeMap::new()) };
}

/// Times `event` was reached on this thread since the last [`reset`].
pub fn count(event: &'static str) -> u64 {
    COUNTS.with(|counts| counts.borrow().get(event).copied().unwrap_or(0))
}

/// Every event's count on this thread since the last [`reset`].
pub fn snapshot() -> BTreeMap<&'static str, u64> {
    COUNTS.with(|counts| counts.borrow().clone())
}

/// Restart this thread's counts.
pub fn reset() {
    COUNTS.with(|counts| counts.borrow_mut().clear());
}

/// Count one occurrence of `event`.
pub fn record(event: &'static str) {
    COUNTS.with(|counts| *counts.borrow_mut().entry(event).or_insert(0) += 1);
}
