//! Deferred callbacks and panic isolation at worker ownership boundaries.
//!
//! Local transitions detach values before invoking user-controlled callbacks.
//! [`Actions`] batches waker notifications and destruction. Other owned values
//! remain in typed retirement batches, with each destructor run through
//! [`Panics::run`] after the local borrow has ended.
//!
//! A cleanup panic must not prevent kernel retirement or sibling cleanup. The
//! first payload is retained until the worker reaches a safe boundary. Later
//! payloads are leaked because their destructors may themselves panic. This
//! rule also applies if the accumulator is destroyed during an existing unwind.

use std::{
    any::Any,
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    task::Waker,
};

/// Payload preserved for delivery after mandatory worker cleanup.
pub(super) type Panic = Box<dyn Any + Send + 'static>;

/// First failure observed while executing independent cleanup actions.
#[derive(Default)]
pub(super) struct Panics {
    /// Retained without invoking its potentially panicking destructor.
    first: Option<Panic>,
}

impl Panics {
    /// Run one callback, retaining its panic without interrupting its siblings.
    pub(super) fn run<T>(&mut self, f: impl FnOnce() -> T) -> Option<T> {
        match catch_unwind(AssertUnwindSafe(f)) {
            Ok(output) => Some(output),
            Err(panic) => {
                self.retain(panic);
                None
            }
        }
    }

    /// Preserve the first failure and suppress destruction of later payloads.
    pub(super) fn retain(&mut self, panic: Panic) {
        if self.first.is_none() {
            self.first = Some(panic);
        } else {
            mem::forget(panic);
        }
    }

    /// Take the failure for root delivery after kernel resources have retired.
    pub(super) fn take(&mut self) -> Option<Panic> {
        self.first.take()
    }

    /// Whether cleanup has observed a failure requiring worker exit.
    pub(super) fn is_pending(&self) -> bool {
        self.first.is_some()
    }
}

impl Drop for Panics {
    fn drop(&mut self) {
        if let Some(panic) = self.first.take() {
            mem::forget(panic);
        }
    }
}

/// Arbitrary waker behavior deferred until local state is no longer borrowed.
pub(super) enum Action {
    /// Notify an observer after committing its state transition.
    Wake(Waker),
    /// Release a displaced or cancelled observer without notifying it.
    Drop(Waker),
}

/// Reusable callback batch owned by the worker loop.
#[derive(Default)]
pub(super) struct Actions {
    /// Callbacks in transition order, retaining allocation across drain turns.
    pending: Vec<Action>,
}

impl Actions {
    /// Reserve callback slots before committing a local transition.
    pub(super) fn reserve(&mut self, additional: usize) {
        self.pending.reserve(additional);
    }

    /// Append a detached callback after reserving sufficient space.
    pub(super) fn push(&mut self, action: Action) {
        self.pending.push(action);
    }

    /// Whether callbacks must run before the worker can park.
    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Execute every callback independently, retaining the first panic.
    pub(super) fn run(&mut self, panics: &mut Panics) {
        for action in self.pending.drain(..) {
            panics.run(|| match action {
                Action::Wake(waker) => waker.wake(),
                Action::Drop(waker) => drop(waker),
            });
        }
    }
}

/// Abort if infrastructure unwinds through kernel retirement.
///
/// Unexpected infrastructure failures cannot release buffers still referenced
/// by staged or submitted SQEs. Deferred user callbacks are caught separately
/// by [`Panics`] while this guard remains armed. Disarm only after retirement.
pub(super) struct RetirementGuard {
    /// Whether freeing kernel-visible resources would still be unsafe.
    armed: bool,
}

impl RetirementGuard {
    /// Protect a mandatory kernel retirement section.
    pub(super) const fn new() -> Self {
        Self { armed: true }
    }

    /// Record that all kernel-visible resources can now be released.
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RetirementGuard {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::{ArcWake, waker};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Callback {
        calls: Arc<AtomicUsize>,
        panics: bool,
    }

    impl ArcWake for Callback {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.calls.fetch_add(1, Ordering::Relaxed);
            assert!(!arc_self.panics, "wake failed");
        }
    }

    #[test]
    fn callback_failure_does_not_skip_siblings() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut actions = Actions::default();
        actions.reserve(3);
        for panics in [true, false] {
            actions.push(Action::Wake(waker(Arc::new(Callback {
                calls: calls.clone(),
                panics,
            }))));
        }
        actions.push(Action::Drop(futures::task::noop_waker()));
        let mut panics = Panics::default();
        actions.run(&mut panics);
        assert!(actions.is_empty());
        assert!(panics.is_pending());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(panics.take().is_some());
        assert!(!panics.is_pending());
        let mut guard = RetirementGuard::new();
        guard.disarm();
    }

    #[test]
    fn secondary_panic_payload_is_not_destroyed() {
        struct Dangerous;
        impl Drop for Dangerous {
            fn drop(&mut self) {
                panic!("payload destructor must not run");
            }
        }
        let mut panics = Panics::default();
        panics.retain(Box::new("first"));
        panics.retain(Box::new(Dangerous));
        assert_eq!(
            panics.take().unwrap().downcast_ref::<&str>(),
            Some(&"first")
        );
    }
}
