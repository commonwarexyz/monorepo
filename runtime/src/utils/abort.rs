//! Cancellation state shared by a spawned task and the handles that abort it.
//!
//! The runtime owns the state (the protocol of [futures::stream::Abortable]) so a poll that leaves
//! a task pending can skip registering a waker that is already registered. Steady-state task polls
//! then only read the shared state, and the task future grows by one pointer.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

cfg_if::cfg_if! {
    if #[cfg(feature = "loom")] {
        use loom::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        /// A linearizable model of [futures::task::AtomicWaker]: a wake that follows a
        /// registration wakes that registration's waker (or one it will wake).
        struct AtomicWaker(Mutex<Option<Waker>>);

        impl AtomicWaker {
            fn new() -> Self {
                Self(Mutex::new(None))
            }

            fn wake(&self) {
                let waker = self.0.lock().unwrap().take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }

        fn register(slot: &AtomicWaker, waker: &Waker) {
            let mut slot = slot.0.lock().unwrap();
            if !slot.as_ref().is_some_and(|old| old.will_wake(waker)) {
                *slot = Some(waker.clone());
            }
        }
    } else {
        use futures::task::AtomicWaker;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        fn register(slot: &AtomicWaker, waker: &Waker) {
            slot.register(waker);
        }
    }
}

/// State shared by an [Abortable] and its abort handles.
///
/// A pending poll of a task only reads this state unless it registers a new waker.
struct Shared {
    /// Set once by [AbortHandle::abort] and never cleared.
    aborted: AtomicBool,
    /// The waker of the last poll that left the [Abortable] pending.
    ///
    /// Only [AbortHandle::abort] wakes (and so empties) this slot, after setting `aborted`.
    waker: AtomicWaker,
    /// The waker a task [Abortable] last registered in `waker`.
    registered: Registered,
}

/// Identifies a registered waker by the data and vtable addresses that [Waker::will_wake]
/// compares (zero before the first registration).
///
/// Only a task [Abortable] accesses it, from its polls, which the executor already orders, so
/// relaxed accesses suffice. It lives in the shared state rather than in the [Abortable] so
/// the task future, and with it the runtime's task allocation, does not grow.
struct Registered {
    data: AtomicUsize,
    vtable: AtomicUsize,
}

/// Aborts the paired [Abortable].
#[derive(Clone)]
pub(crate) struct AbortHandle {
    shared: Arc<Shared>,
}

/// The task side of an [AbortHandle], consumed by [Abortable::new] or [Abortable::task].
pub(crate) struct AbortRegistration {
    shared: Arc<Shared>,
}

/// The output of an [Abortable] that was aborted before its future completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Aborted;

impl AbortHandle {
    /// Creates a handle and the registration its [Abortable] consumes.
    pub(crate) fn new_pair() -> (Self, AbortRegistration) {
        let shared = Arc::new(Shared {
            aborted: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            registered: Registered {
                data: AtomicUsize::new(0),
                vtable: AtomicUsize::new(0),
            },
        });
        (
            Self {
                shared: shared.clone(),
            },
            AbortRegistration { shared },
        )
    }

    /// Aborts the paired [Abortable]: its next poll resolves to [Aborted] without polling the
    /// wrapped future, and a pending task is woken so that poll happens.
    ///
    /// A future that already completed is unaffected.
    pub(crate) fn abort(&self) {
        // The wake synchronizes with the poll it schedules, which then observes the flag.
        self.shared.aborted.store(true, Ordering::Relaxed);
        self.shared.waker.wake();
    }

    /// Returns whether [AbortHandle::abort] was called.
    #[cfg(test)]
    pub(crate) fn is_aborted(&self) -> bool {
        self.shared.aborted.load(Ordering::Relaxed)
    }
}

/// A future that resolves to [Aborted] once its [AbortHandle] aborts it.
///
/// `TASK` marks the future of a runtime task (see [Abortable::task]), whose pending polls skip
/// registering an unchanged waker.
pub(crate) struct Abortable<F, const TASK: bool = false> {
    future: F,
    shared: Arc<Shared>,
}

impl<F> Abortable<F> {
    /// Wraps `future` so the handle paired with `registration` can abort it.
    ///
    /// Every pending poll registers its waker, so any executor may poll the result.
    pub(crate) fn new(future: F, registration: AbortRegistration) -> Self {
        Self {
            future,
            shared: registration.shared,
        }
    }
}

impl<F> Abortable<F, true> {
    /// Wraps the future of a runtime task so the handle paired with `registration` can abort
    /// it, without registering a waker that is already registered.
    ///
    /// Only the task future that `Handle::init` builds may own the result. The runtime's
    /// executors poll that future only with wakers of its task, and it passes their context
    /// through, so whichever waker is registered wakes the task that a later poll's waker wakes.
    pub(crate) fn task(future: F, registration: AbortRegistration) -> Self {
        Self {
            future,
            shared: registration.shared,
        }
    }
}

impl<F, const TASK: bool> Abortable<F, TASK> {
    /// Returns whether the paired [AbortHandle] aborted this future.
    pub(crate) fn is_aborted(&self) -> bool {
        self.shared.aborted.load(Ordering::Relaxed)
    }

    /// Registers `waker` for the abort wake.
    ///
    /// A task wrapper does not register a waker equal to the last registered one again (an
    /// unequal one replaces it, so the slot follows the latest waker). The slot keeps holding a
    /// waker of the task until [AbortHandle::abort] wakes it, and abort sets the flag first. So
    /// re-registering would change nothing, and a concurrent abort still wakes the task, whose
    /// next poll observes the flag (a wake happens before the poll it schedules). A
    /// registration that raced an abort's wake may leave the slot empty, but the check that
    /// follows it in [Abortable::poll] observes that abort.
    ///
    /// Other wrappers always register. Their pollers may change tasks, and equal addresses
    /// identify the same task only while the waker that had them lives: the slot holds a clone,
    /// which an executor may represent differently while it reuses the original's addresses.
    fn register(&self, waker: &Waker) {
        if TASK {
            let registered = &self.shared.registered;
            let data = waker.data().addr();
            let vtable = std::ptr::from_ref(waker.vtable()).addr();
            if registered.data.load(Ordering::Relaxed) == data
                && registered.vtable.load(Ordering::Relaxed) == vtable
            {
                return;
            }
            registered.data.store(data, Ordering::Relaxed);
            registered.vtable.store(vtable, Ordering::Relaxed);
        }
        register(&self.shared.waker, waker);
    }
}

impl<F: Future, const TASK: bool> Future for Abortable<F, TASK> {
    type Output = Result<F::Output, Aborted>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: Only `future` is structurally pinned. `Abortable` has no `Drop` impl, is
        // `Unpin` only when `F` is, and never moves `future` out of this reference.
        let this = unsafe { self.get_unchecked_mut() };
        if this.is_aborted() {
            return Poll::Ready(Err(Aborted));
        }

        // SAFETY: See above, `future` stays pinned for as long as `self` is.
        let future = unsafe { Pin::new_unchecked(&mut this.future) };
        if let Poll::Ready(output) = future.poll(cx) {
            return Poll::Ready(Ok(output));
        }

        // Register for the abort wake, then check again so an abort that raced the poll is
        // not lost. Registration orders this check after any abort it observed.
        this.register(cx.waker());
        if this.is_aborted() {
            return Poll::Ready(Err(Aborted));
        }
        Poll::Pending
    }
}

#[cfg(all(test, not(feature = "loom")))]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;
    use commonware_utils::sync::Mutex;
    use futures::{future, task::ArcWake};
    use std::{
        mem::ManuallyDrop,
        sync::atomic::{AtomicBool as StdAtomicBool, AtomicUsize},
        task::{RawWaker, RawWakerVTable},
        thread,
    };

    struct Counter(AtomicUsize);

    impl ArcWake for Counter {
        fn wake_by_ref(arc_self: &std::sync::Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter() -> (std::sync::Arc<Counter>, Waker) {
        let counter = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let waker = futures::task::waker(counter.clone());
        (counter, waker)
    }

    fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(waker))
    }

    /// Wake counts of two wakers that share their data pointer, one per vtable.
    struct Twins([AtomicUsize; 2]);

    static TWIN_VTABLES: [RawWakerVTable; 2] = [twin_vtable::<0>(), twin_vtable::<1>()];

    const fn twin_vtable<const I: usize>() -> RawWakerVTable {
        RawWakerVTable::new(twin_clone::<I>, twin_wake::<I>, twin_wake::<I>, twin_drop)
    }

    fn twin_waker<const I: usize>(twins: &Twins) -> Waker {
        let raw = RawWaker::new(std::ptr::from_ref(twins).cast(), &TWIN_VTABLES[I]);
        // SAFETY: The vtable functions only read the `Twins` behind the data pointer, which
        // the test keeps alive until every waker pointing at it is dropped.
        unsafe { Waker::from_raw(raw) }
    }

    const unsafe fn twin_clone<const I: usize>(data: *const ()) -> RawWaker {
        RawWaker::new(data, &TWIN_VTABLES[I])
    }

    unsafe fn twin_wake<const I: usize>(data: *const ()) {
        // SAFETY: `data` points at a live `Twins` (see `twin_waker`).
        let twins = unsafe { &*data.cast::<Twins>() };
        twins.0[I].fetch_add(1, Ordering::SeqCst);
    }

    const unsafe fn twin_drop(_: *const ()) {}

    /// The executor record a slot waker points at. The executor assigns it to another task once
    /// the waker is dropped, while a clone points at its task directly.
    struct Slot(Mutex<std::sync::Arc<Counter>>);

    static SLOT_VTABLE: RawWakerVTable =
        RawWakerVTable::new(slot_clone, slot_wake, slot_wake, slot_drop);

    fn slot_waker(slot: &Slot) -> Waker {
        let raw = RawWaker::new(std::ptr::from_ref(slot).cast(), &SLOT_VTABLE);
        // SAFETY: The vtable functions only use the `Slot` behind the data pointer, which the
        // test keeps alive until every waker pointing at it is dropped.
        unsafe { Waker::from_raw(raw) }
    }

    unsafe fn slot_clone(data: *const ()) -> RawWaker {
        // SAFETY: `data` points at a live `Slot` (see `slot_waker`).
        let slot = unsafe { &*data.cast::<Slot>() };
        // The clone takes over the waker's reference to the task, which its vtable releases.
        let waker = ManuallyDrop::new(futures::task::waker(slot.0.lock().clone()));
        RawWaker::new(waker.data(), waker.vtable())
    }

    unsafe fn slot_wake(data: *const ()) {
        // SAFETY: `data` points at a live `Slot` (see `slot_waker`).
        let slot = unsafe { &*data.cast::<Slot>() };
        ArcWake::wake_by_ref(&slot.0.lock());
    }

    const unsafe fn slot_drop(_: *const ()) {}

    /// The wrapper adds only the shared-state pointer to the task future, so it does not grow
    /// the runtime's task allocation.
    #[test]
    fn wrapper_adds_one_pointer() {
        assert_eq!(
            size_of::<Abortable<future::Pending<()>, true>>(),
            size_of::<usize>()
        );
    }

    #[test]
    fn abort_before_poll_skips_future() {
        let (handle, registration) = AbortHandle::new_pair();
        handle.abort();
        assert!(handle.is_aborted());
        let mut future = Abortable::new(future::lazy(|_| panic!("polled")), registration);
        let (_, waker) = counter();
        assert_eq!(poll(&mut future, &waker), Poll::Ready(Err(Aborted)));
    }

    #[test]
    fn abort_wakes_latest_waker() {
        let (handle, registration) = AbortHandle::new_pair();
        let mut future = Abortable::task(future::pending::<()>(), registration);
        let (first, first_waker) = counter();
        let (second, second_waker) = counter();
        assert!(poll(&mut future, &first_waker).is_pending());
        assert!(poll(&mut future, &first_waker).is_pending());
        assert!(poll(&mut future, &second_waker).is_pending());
        handle.abort();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll(&mut future, &second_waker), Poll::Ready(Err(Aborted)));
    }

    #[test]
    fn abort_wakes_repeatedly_registered_waker() {
        let (handle, registration) = AbortHandle::new_pair();
        let mut future = Abortable::task(future::pending::<()>(), registration);
        let (counter, waker) = counter();
        for _ in 0..3 {
            assert!(poll(&mut future, &waker).is_pending());
        }
        handle.abort();
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll(&mut future, &waker), Poll::Ready(Err(Aborted)));
    }

    /// A task wrapper compares vtables as well as data pointers: a waker that shares only its
    /// data pointer with the registered one replaces it.
    #[test]
    fn task_registers_waker_with_new_vtable() {
        let twins = Twins([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let (handle, registration) = AbortHandle::new_pair();
        let mut future = Abortable::task(future::pending::<()>(), registration);
        assert!(poll(&mut future, &twin_waker::<0>(&twins)).is_pending());
        assert!(poll(&mut future, &twin_waker::<1>(&twins)).is_pending());
        handle.abort();
        assert_eq!(twins.0[0].load(Ordering::SeqCst), 0);
        assert_eq!(twins.0[1].load(Ordering::SeqCst), 1);
    }

    /// A waker's addresses identify its task only while it lives. Once an executor reuses them
    /// for another task, a wrapper that the new task polls registers the new task's waker, even
    /// though the registered clone (represented differently) still wakes the old task.
    #[test]
    fn abort_wakes_task_behind_reused_waker_addresses() {
        let first = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let second = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let slot = Slot(Mutex::new(first.clone()));
        let (handle, registration) = AbortHandle::new_pair();
        let mut future = Abortable::new(future::pending::<()>(), registration);
        let waker = slot_waker(&slot);
        assert!(poll(&mut future, &waker).is_pending());
        drop(waker);
        *slot.0.lock() = second.clone();
        let waker = slot_waker(&slot);
        assert!(poll(&mut future, &waker).is_pending());
        handle.abort();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll(&mut future, &waker), Poll::Ready(Err(Aborted)));
    }

    #[test]
    fn abort_after_completion_keeps_output() {
        let (handle, registration) = AbortHandle::new_pair();
        let mut future = Abortable::new(future::ready(7), registration);
        let (_, waker) = counter();
        assert_eq!(poll(&mut future, &waker), Poll::Ready(Ok(7)));
        handle.abort();
        assert!(handle.is_aborted());
    }

    /// A poller and an aborter race on real threads. Every round ends aborted, and a poll that
    /// returns pending is always followed by a wake.
    #[test]
    fn concurrent_abort_and_poll() {
        let rounds = if cfg!(miri) { 100 } else { 2_000 };
        for _ in 0..rounds {
            let (handle, registration) = AbortHandle::new_pair();
            let start = std::sync::Arc::new(StdAtomicBool::new(false));
            let done = std::sync::Arc::new(StdAtomicBool::new(false));
            let aborter = {
                let start = start.clone();
                let done = done.clone();
                thread::spawn(move || {
                    while !start.load(Ordering::Acquire) {
                        std::hint::spin_loop();
                    }
                    handle.abort();
                    done.store(true, Ordering::Release);
                })
            };
            let mut future = Abortable::task(future::pending::<()>(), registration);
            let (counter, waker) = counter();
            start.store(true, Ordering::Release);
            let mut seen = 0;
            loop {
                match poll(&mut future, &waker) {
                    Poll::Ready(result) => {
                        assert_eq!(result, Err(Aborted));
                        break;
                    }
                    // Poll again only once woken, as an executor would.
                    Poll::Pending => loop {
                        let wakes = counter.0.load(Ordering::SeqCst);
                        if wakes > seen {
                            seen = wakes;
                            break;
                        }
                        // Once `done` is set, the abort's wake is visible.
                        let finished = done.load(Ordering::Acquire);
                        if finished && counter.0.load(Ordering::SeqCst) == seen {
                            panic!("abort wake lost");
                        }
                        std::hint::spin_loop();
                    },
                }
            }
            aborter.join().unwrap();
        }
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    //! Models the abort protocol: an abort racing a poll that leaves the task pending must
    //! either be observed by that poll or wake the waker it registered (the latest one).
    use super::*;
    use loom::{sync::atomic::AtomicUsize, thread};
    use std::task::{RawWaker, RawWakerVTable};

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);

    /// A waker over a leaked counter (loom atomics live only within one model execution, and
    /// the few leaked counters per execution are bounded).
    fn counter() -> (&'static AtomicUsize, Waker) {
        let counter: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
        let raw = RawWaker::new(std::ptr::from_ref(counter).cast(), &VTABLE);
        // SAFETY: The vtable functions treat the data pointer as a leaked, never freed
        // `AtomicUsize`, which is valid for the rest of the program.
        (counter, unsafe { Waker::from_raw(raw) })
    }

    unsafe fn clone(data: *const ()) -> RawWaker {
        RawWaker::new(data, &VTABLE)
    }

    unsafe fn wake(data: *const ()) {
        // SAFETY: Same contract as `wake_by_ref`.
        unsafe { wake_by_ref(data) }
    }

    unsafe fn wake_by_ref(data: *const ()) {
        // SAFETY: `data` is a leaked `AtomicUsize` (see `counter`).
        let counter = unsafe { &*data.cast::<AtomicUsize>() };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    const unsafe fn drop_waker(_: *const ()) {}

    fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(waker))
    }

    /// Runs `polls_before` pending polls of a task wrapper with one waker, then races an abort
    /// against one more poll, with the same waker when `same_waker` is set (which skips
    /// registration after an earlier poll) and with a new waker otherwise.
    fn race(polls_before: usize, same_waker: bool) {
        loom::model(move || {
            let (handle, registration) = AbortHandle::new_pair();
            let mut future = Abortable::task(std::future::pending::<()>(), registration);
            let (first, first_waker) = counter();
            for _ in 0..polls_before {
                assert!(poll(&mut future, &first_waker).is_pending());
            }
            let (counter, waker) = if same_waker {
                (first, first_waker.clone())
            } else {
                counter()
            };

            let aborter = thread::spawn(move || handle.abort());
            let result = poll(&mut future, &waker);
            aborter.join().unwrap();

            match result {
                Poll::Ready(result) => assert_eq!(result, Err(Aborted)),
                Poll::Pending => {
                    // The pending poll's waker was woken, and the woken poll sees the abort.
                    assert!(counter.load(Ordering::SeqCst) >= 1, "abort wake lost");
                    assert_eq!(poll(&mut future, &waker), Poll::Ready(Err(Aborted)));
                }
            }
        });
    }

    #[test]
    fn abort_races_first_poll() {
        race(0, true);
    }

    #[test]
    fn abort_races_repeat_poll_same_waker() {
        race(1, true);
    }

    #[test]
    fn abort_races_repeat_poll_new_waker() {
        race(1, false);
    }
}
