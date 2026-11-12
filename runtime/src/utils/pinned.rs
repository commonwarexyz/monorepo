//! A future built and polled on one thread.

use std::{
    future::Future,
    mem::ManuallyDrop,
    pin::Pin,
    task::{Context, Poll},
    thread::{self, ThreadId},
};

/// Progress of a [Pinned] future.
enum State<F, Fut> {
    /// The factory has not run.
    Factory(F),
    /// The factory ran on `owner`, which alone may poll or drop `future`.
    Running {
        owner: ThreadId,
        future: ManuallyDrop<Pin<Box<Fut>>>,
    },
    /// The future completed or was released.
    Done,
}

/// A [Send] future that runs a factory on its first poll and then polls the future the factory
/// returned, which need not be [Send], on that same thread.
///
/// Polling from any other thread panics. Dropping from any other thread leaks the inner future
/// rather than running its destructor there.
pub(crate) struct Pinned<F, Fut> {
    state: State<F, Fut>,
}

impl<F, Fut> Pinned<F, Fut>
where
    F: FnOnce() -> Fut,
    Fut: Future,
{
    /// Wrap `factory`, which runs when the returned future is first polled.
    pub(crate) const fn new(factory: F) -> Self {
        Self {
            state: State::Factory(factory),
        }
    }
}

// SAFETY: The only non-Send value is `Fut`, which exists only in `State::Running`. It is created
// on `owner` by the first poll, and `poll` and `drop` touch it only on `owner` (other threads
// panic or leak it), so it is never accessed from a thread other than the one that created it.
// Moving the `Pinned` itself only moves the `Box` pointer, not the future it points to.
unsafe impl<F: Send, Fut> Send for Pinned<F, Fut> {}

// The inner future is boxed, so it stays pinned while `Pinned` moves.
impl<F, Fut> Unpin for Pinned<F, Fut> {}

impl<F, Fut> Future for Pinned<F, Fut>
where
    F: FnOnce() -> Fut,
    Fut: Future,
{
    type Output = Fut::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let current = thread::current().id();
        if matches!(this.state, State::Factory(_)) {
            let State::Factory(factory) = std::mem::replace(&mut this.state, State::Done) else {
                unreachable!("state checked above");
            };
            this.state = State::Running {
                owner: current,
                future: ManuallyDrop::new(Box::pin(factory())),
            };
        }
        let State::Running { owner, future } = &mut this.state else {
            panic!("pinned future polled after completion");
        };
        assert_eq!(*owner, current, "pinned future polled from another thread");
        let output = future.as_mut().poll(cx);
        if output.is_ready() {
            this.release();
        }
        output
    }
}

impl<F, Fut> Pinned<F, Fut> {
    /// Drop the inner future if this is its owner's thread, else leak it.
    fn release(&mut self) {
        if let State::Running { owner, mut future } = std::mem::replace(&mut self.state, State::Done)
            && owner == thread::current().id()
        {
            // SAFETY: `future` was taken out of `self.state` and is not used again.
            unsafe { ManuallyDrop::drop(&mut future) };
        }
    }
}

impl<F, Fut> Drop for Pinned<F, Fut> {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use futures::{FutureExt as _, executor::block_on};
    use std::{
        cell::Cell,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    const fn assert_send<T: Send>(_: &T) {}

    #[test]
    fn test_runs_non_send_future() {
        let pinned = Pinned::new(|| {
            let counter = Rc::new(Cell::new(0));
            async move {
                futures::future::ready(()).await;
                counter.set(counter.get() + 1);
                counter.get()
            }
        });
        assert_send(&pinned);
        assert_eq!(block_on(pinned), 1);
    }

    #[test]
    fn test_factory_runs_on_polling_thread() {
        let pinned = Pinned::new(|| async { thread::current().id() });
        let caller = thread::current().id();
        let polled = thread::spawn(move || (thread::current().id(), block_on(pinned)))
            .join()
            .unwrap();
        assert_ne!(polled.0, caller);
        assert_eq!(polled.0, polled.1);
    }

    #[test]
    fn test_unpolled_drop_on_other_thread_drops_factory() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = Flag(dropped.clone());
        let pinned = Pinned::new(move || {
            let _flag = flag;
            async {}
        });
        thread::spawn(move || drop(pinned)).join().unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn test_drop_on_owner_runs_destructor() {
        let dropped = Rc::new(Cell::new(false));
        struct Flag(Rc<Cell<bool>>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let flag = Flag(dropped.clone());
        let mut pinned = Pinned::new(move || async move {
            let _flag = flag;
            futures::future::pending::<()>().await;
        });
        assert!(pinned.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref())).is_pending());
        assert!(!dropped.get());
        drop(pinned);
        assert!(dropped.get());
    }

    #[test]
    #[cfg_attr(miri, ignore = "leaks the inner future by design")]
    fn test_drop_on_other_thread_leaks() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = Flag(dropped.clone());
        let mut pinned = Pinned::new(move || {
            let marker = Rc::new(());
            async move {
                let _flag = flag;
                let _marker = marker;
                futures::future::pending::<()>().await;
            }
        });
        assert!(pinned.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref())).is_pending());
        thread::spawn(move || drop(pinned)).join().unwrap();
        assert!(!dropped.load(Ordering::SeqCst));
    }

    #[test]
    #[cfg_attr(miri, ignore = "leaks the inner future by design")]
    fn test_poll_on_other_thread_panics() {
        let mut pinned = Pinned::new(|| async {
            futures::future::pending::<()>().await;
        });
        assert!(pinned.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref())).is_pending());
        let result = thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = pinned.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref()));
            }));
            // Leak rather than drop here so the test checks only the poll.
            std::mem::forget(pinned);
            result
        })
        .join()
        .unwrap();
        assert!(result.is_err());
    }
}
