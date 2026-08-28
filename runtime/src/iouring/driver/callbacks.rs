//! Deferred RawWaker callbacks for driver state transitions.
//!
//! Cloning, dropping, or waking a `Waker` invokes externally supplied code.
//! Driver transitions therefore reserve action storage before mutation,
//! commit owner state while it is borrowed, then execute every detached
//! callback after releasing that borrow.

use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    task::Waker,
};

/// Deferred action for a task waker detached from owner state.
pub(super) enum WakerAction {
    /// Drop a stored waker after its owner state is disarmed.
    Drop(Waker),
    /// Invoke a waker after the state change it observes is committed.
    Wake(Waker),
}

/// Append-only destination for detached waker actions.
///
/// The driver uses its reusable action vector. Future poll and drop paths use
/// a fixed batch for the one or two actions produced by a single transition.
pub(super) trait WakerActionSink {
    /// Ensure room before the state transition that will produce actions.
    fn reserve(&mut self, additional: usize);

    /// Append one action whose callback must run after owner state is released.
    fn push(&mut self, action: WakerAction);
}

impl WakerActionSink for Vec<WakerAction> {
    fn reserve(&mut self, additional: usize) {
        Self::reserve(self, additional);
    }

    fn push(&mut self, action: WakerAction) {
        Self::push(self, action);
    }
}

/// Deferred actions produced by one state transition.
///
/// A single admission, cancellation, grant, poll, or orphan transition
/// produces at most two actions. Batched loop paths use a vector directly.
pub(super) struct DeferredWakerActions {
    /// Fixed storage for the transition's actions.
    inline: [Option<WakerAction>; 2],
    /// Number of initialized entries at the start of `inline`.
    inline_len: usize,
}

impl DeferredWakerActions {
    /// Construct an empty batch without allocating.
    pub(super) const fn new() -> Self {
        Self {
            inline: [None, None],
            inline_len: 0,
        }
    }
}

impl WakerActionSink for DeferredWakerActions {
    fn reserve(&mut self, additional: usize) {
        assert!(
            additional <= self.inline.len() - self.inline_len,
            "waker action batch exceeded fixed storage"
        );
    }

    fn push(&mut self, action: WakerAction) {
        self.reserve(1);
        self.inline[self.inline_len] = Some(action);
        self.inline_len += 1;
    }
}

impl IntoIterator for DeferredWakerActions {
    type Item = WakerAction;
    type IntoIter = std::iter::Flatten<std::array::IntoIter<Option<WakerAction>, 2>>;

    fn into_iter(self) -> Self::IntoIter {
        self.inline.into_iter().flatten()
    }
}

/// Run every detached waker action and retain the first callback panic.
///
/// Owner state is committed before this function runs. Continuing the batch
/// ensures a panicking callback cannot strand later waiters whose state has
/// already advanced. Outside an existing unwind, the first payload is resumed
/// after the batch. During an existing unwind it is leaked to avoid a second
/// panic abort. Secondary payloads are always leaked because their destructors
/// may panic while the first payload is retained.
pub(super) fn run_waker_actions(actions: impl IntoIterator<Item = WakerAction>) {
    let already_panicking = std::thread::panicking();
    let mut first_panic = None;
    for action in actions {
        let result = catch_unwind(AssertUnwindSafe(|| match action {
            WakerAction::Drop(waker) => drop(waker),
            WakerAction::Wake(waker) => waker.wake(),
        }));
        if let Err(payload) = result {
            if first_panic.is_none() {
                first_panic = Some(payload);
            } else {
                std::mem::forget(payload);
            }
        }
    }
    if let Some(payload) = first_panic {
        if already_panicking {
            std::mem::forget(payload);
        } else {
            resume_unwind(payload);
        }
    }
}
