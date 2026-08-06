//! Synchronization primitives replaced by Loom models during concurrency tests.

#[cfg(not(feature = "loom"))]
pub(super) use commonware_utils::sync::Mutex;
#[cfg(not(feature = "loom"))]
pub(super) use futures::task::AtomicWaker;
#[cfg(feature = "loom")]
pub(super) use loom::sync::Arc as EntryArc;
#[cfg(not(feature = "loom"))]
pub(super) use std::sync::Arc as EntryArc;
#[cfg(feature = "loom")]
use std::task::Waker;

/// Loom mutex with the non-poisoning API used by the production protocol.
#[cfg(feature = "loom")]
pub(super) struct Mutex<T>(loom::sync::Mutex<T>);

#[cfg(feature = "loom")]
impl<T> Mutex<T> {
    /// Creates one modeled mutex around the supplied state.
    #[inline]
    pub(super) fn new(value: T) -> Self {
        Self(loom::sync::Mutex::new(value))
    }

    /// Locks modeled state and treats a prior test panic as fatal.
    #[inline]
    pub(super) fn lock(&self) -> loom::sync::MutexGuard<'_, T> {
        self.0.lock().expect("modeled timer mutex poisoned")
    }
}

/// Loom atomic waker with the Futures API used by the production protocol.
#[cfg(feature = "loom")]
pub(super) struct AtomicWaker(loom::future::AtomicWaker);

#[cfg(feature = "loom")]
impl AtomicWaker {
    /// Creates one empty modeled waker slot.
    pub(super) fn new() -> Self {
        Self(loom::future::AtomicWaker::new())
    }

    /// Registers the latest task waker.
    pub(super) fn register(&self, waker: &Waker) {
        self.0.register_by_ref(waker);
    }

    /// Takes the currently registered task waker.
    pub(super) fn take(&self) -> Option<Waker> {
        self.0.take_waker()
    }

    /// Takes and wakes the currently registered task.
    pub(super) fn wake(&self) {
        self.0.wake();
    }
}
