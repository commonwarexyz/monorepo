//! Task machinery for the io_uring runtime executor.
//!
//! A spawned task is one [TaskCell] allocation: the concrete future stored
//! inline, the identity behind a raw-vtable waker sharing that allocation,
//! and a queued latch that coalesces repeated wakes into one ready-queue
//! entry. Polling crosses a single type-erased boundary ([Erased]) so the
//! compiler sees the concrete future type inside the monomorphized cell.
//! [Tasks] owns the ready queue and the arena of running tasks: completed
//! slots are recycled for later spawns, and futures stay pinned to the
//! worker thread that polls them ([Affine]) while registration and wakes may
//! arrive from any thread (a foreign wake latches the ring's out-of-band
//! wake state). Teardown clears the arena and rejects racing registrations
//! instead of leaking tasks nothing will ever poll.

// In scope for the intra-doc links in this module's documentation.
#[allow(unused_imports)]
use super::Executor;
use crate::iouring::driver::{Affine, waker::Waker as RingWaker};
#[allow(unused_imports)]
use crate::{Error, Handle};
use commonware_utils::sync::Mutex;
use futures::task::{ArcWake, waker};
use std::{
    cell::RefCell,
    future::Future,
    mem::{ManuallyDrop, replace, take},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{self, Poll},
    thread::{self, ThreadId},
};

/// Type-erased boundary for a task in the arena.
///
/// The concrete future lives inline in the task's single `Arc` allocation,
/// so the only dynamic dispatch on the poll path is this trait: inside the
/// monomorphized [TaskCell] methods the compiler sees the concrete future
/// type end to end.
pub(super) trait Erased: Send + Sync {
    /// Poll the stored future, returning true when this call completed it
    /// (the caller then frees the task's arena slot).
    fn poll(self: Arc<Self>) -> bool;

    /// Resolve the task without polling: drop the future in place (which
    /// resolves any join handle with [Error::Closed]).
    fn clear(&self);

    /// The arena slot owning this task.
    fn slot(&self) -> usize;
}

/// A spawned task: one allocation holding the concrete future and the
/// identity behind its raw-vtable waker. Results reach the task's handle
/// through the wrapper built by [Handle::init], not through the cell.
struct TaskCell<F>
where
    F: Future<Output = ()>,
{
    /// Arena slot to free at completion.
    slot: usize,
    /// Re-enqueue target for wakes.
    tasks: Weak<Tasks>,
    /// Whether the task is already in the ready queue (or terminally done).
    ///
    /// A waker may legally fire many times before its task is polled, and
    /// each unguarded push is a full re-poll (a future waking itself twice
    /// per poll would double the queue every executor turn). Only the wake
    /// that transitions this latch queues the task, and the rest coalesce. The
    /// latch is released immediately before polling a live future and set
    /// terminally once the future is gone, so late wakes on a completed or
    /// cleared cell buy at most one dead poll.
    queued: AtomicBool,
    /// The future, polled and cleared only on the owning worker thread (a
    /// spawning thread builds the cell but never touches the future), so no
    /// lock is needed.
    ///
    /// `None` once the future completed or teardown cleared it.
    future: Affine<RefCell<Option<F>>>,
}

impl<F> TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    /// Waker vtable sharing the task's own allocation: cloning bumps the
    /// task's strong count and waking enqueues the task pointer directly, so
    /// wakes carry no id and polls need no registry lookup.
    const VTABLE: task::RawWakerVTable = task::RawWakerVTable::new(
        Self::waker_clone,
        Self::waker_wake,
        Self::waker_wake_by_ref,
        Self::waker_drop,
    );

    /// Manufacture a waker backed by this task's allocation.
    ///
    /// Waker identity is (data pointer, vtable), both stable for the task's
    /// lifetime, so every poll presents an identical waker and
    /// `Waker::will_wake` fast paths (e.g. the driver's slot refreshes) hold.
    fn waker(self: &Arc<Self>) -> task::Waker {
        let ptr = Arc::into_raw(Arc::clone(self)).cast::<()>();
        // SAFETY: the vtable functions uphold the RawWaker contract over the
        // Arc reference encoded in `ptr`.
        unsafe { task::Waker::from_raw(task::RawWaker::new(ptr, &Self::VTABLE)) }
    }

    unsafe fn waker_clone(ptr: *const ()) -> task::RawWaker {
        // SAFETY: `ptr` encodes an Arc<Self> reference from [Self::waker].
        unsafe { Arc::increment_strong_count(ptr.cast::<Self>()) };
        task::RawWaker::new(ptr, &Self::VTABLE)
    }

    unsafe fn waker_wake(ptr: *const ()) {
        // SAFETY: consumes the waker's Arc reference.
        let cell = unsafe { Arc::from_raw(ptr.cast::<Self>()) };
        cell.enqueue();
    }

    unsafe fn waker_wake_by_ref(ptr: *const ()) {
        // SAFETY: borrows the waker's Arc reference without consuming it.
        let cell = unsafe { ManuallyDrop::new(Arc::from_raw(ptr.cast::<Self>())) };
        cell.enqueue();
    }

    unsafe fn waker_drop(ptr: *const ()) {
        // SAFETY: releases the waker's Arc reference.
        drop(unsafe { Arc::from_raw(ptr.cast::<Self>()) });
    }

    /// Re-enqueue this task for polling.
    ///
    /// If the upgrade fails, the runtime already exited and the wake is a
    /// no-op (e.g. data holding a waker dropped after `start` returned).
    fn enqueue(self: &Arc<Self>) {
        // Coalesce repeated wakes: only the latch transition queues the task.
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(tasks) = self.tasks.upgrade() {
            tasks.queue(Arc::clone(self) as Arc<dyn Erased>);
        }
    }
}

impl<F> Erased for TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn poll(self: Arc<Self>) -> bool {
        let waker = self.waker();
        let mut cx = task::Context::from_waker(&waker);
        self.future.with(|cell| {
            let mut slot = cell.borrow_mut();
            // A wake that raced completion may re-poll a dead cell: its slot
            // was already freed, so report no completion. The queued latch
            // stays set (the wake that scheduled this poll set it), so later
            // wakes cannot re-queue the cell again.
            let Some(future) = slot.as_mut() else {
                return false;
            };
            // Release the queued latch before polling so wakes during the
            // poll re-queue the task. The acquiring swap pairs with the
            // release half of coalesced wakes' latch RMWs (which bypass the
            // ready-queue mutex), making their published state visible to
            // this poll.
            self.queued.swap(false, Ordering::AcqRel);
            // SAFETY: the future lives inside this task's Arc allocation and
            // is never moved out of it: completion (below) and teardown
            // ([Erased::clear]) both drop it in place by overwriting the
            // option with None.
            let future = unsafe { Pin::new_unchecked(future) };
            match future.poll(&mut cx) {
                Poll::Ready(()) => {
                    *slot = None;
                    // Terminal: late wakes must not re-queue a dead cell.
                    self.queued.store(true, Ordering::Relaxed);
                    true
                }
                Poll::Pending => false,
            }
        })
    }

    fn clear(&self) {
        // Terminal latch first: teardown-era late wakes must not re-queue a
        // cell nothing will poll again.
        self.queued.store(true, Ordering::Relaxed);
        self.future.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }

    fn slot(&self) -> usize {
        self.slot
    }
}

/// A waker for the root task, which lives on the runtime thread's stack (so
/// its typed output is captured un-erased) rather than in the arena.
struct RootWaker {
    tasks: Weak<Tasks>,
}

impl ArcWake for RootWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // If the upgrade fails, the runtime already exited.
        if let Some(tasks) = arc_self.tasks.upgrade() {
            tasks.queue_root();
        }
    }
}

/// The arena of running tasks, plus whether the executor has shut down.
struct Running {
    /// Task slots. Freed slots are recycled through `free`.
    slots: Vec<Option<Arc<dyn Erased>>>,
    /// Recycled slot indices.
    free: Vec<usize>,
    /// Set once the executor clears the arena at teardown. Registrations that
    /// race teardown are rejected (resolving their handles with
    /// [Error::Closed]) instead of leaking into an arena nothing will ever
    /// poll again.
    closed: bool,
}

/// The tasks being executed by the [Executor].
pub(super) struct Tasks {
    /// Tasks ready to be polled, queued by pointer (no ids, no lookups).
    ready: Mutex<Vec<Arc<dyn Erased>>>,
    /// Whether the root task is ready to be polled. Starts true for the
    /// kickoff poll.
    root_ready: AtomicBool,
    /// The arena owning all running tasks (for teardown enumeration).
    running: Mutex<Running>,
    /// The worker thread that polls (and tears down) these tasks. Task cells
    /// are pinned to it so registration works from any thread.
    owner: ThreadId,
    /// Wakes the runtime thread when a task becomes ready.
    ///
    /// Latches the event loop's out-of-band wake state so a parked executor
    /// (futex or `submit_and_wait`) observes the enqueue from any thread.
    unpark: RingWaker,
}

impl Tasks {
    /// Create a new task queue owned by the calling (worker) thread.
    pub(super) fn new(unpark: RingWaker) -> Self {
        Self {
            ready: Mutex::new(Vec::new()),
            root_ready: AtomicBool::new(true),
            running: Mutex::new(Running {
                slots: Vec::new(),
                free: Vec::new(),
                closed: false,
            }),
            owner: thread::current().id(),
            unpark,
        }
    }

    /// Build the root task's waker.
    pub(super) fn root_waker(arc_self: &Arc<Self>) -> task::Waker {
        waker(Arc::new(RootWaker {
            tasks: Arc::downgrade(arc_self),
        }))
    }

    /// Register a task for `future` and queue its first poll.
    ///
    /// Returns false (dropping the future) when the executor is already
    /// tearing down.
    pub(super) fn register<F>(arc_self: &Arc<Self>, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cell = {
            let mut running = arc_self.running.lock();
            if running.closed {
                return false;
            }
            let slot = running.free.pop().unwrap_or_else(|| {
                running.slots.push(None);
                running.slots.len() - 1
            });
            let cell = Arc::new(TaskCell {
                slot,
                tasks: Arc::downgrade(arc_self),
                // Latched: the cell is queued for its first poll below.
                queued: AtomicBool::new(true),
                // Pin the cell to the worker that polls it, not to the
                // registering thread: spawns may arrive from any thread
                // through a moved context.
                future: Affine::pinned(arc_self.owner, RefCell::new(Some(future))),
            });
            running.slots[slot] = Some(Arc::clone(&cell) as Arc<dyn Erased>);
            cell
        };

        // Queue the first poll.
        arc_self.queue(cell as Arc<dyn Erased>);
        true
    }

    /// Enqueue an already registered task to be polled.
    fn queue(&self, task: Arc<dyn Erased>) {
        self.ready.lock().push(task);
        self.unpark_foreign();
    }

    /// Mark the root task ready to be polled.
    fn queue_root(&self) {
        self.root_ready.store(true, Ordering::Release);
        self.unpark_foreign();
    }

    /// Latch the loop's out-of-band wake state when called from any thread
    /// but the worker's own.
    ///
    /// A same-thread wake can only happen while the loop is awake (polling a
    /// task or draining completions), and the loop rechecks `has_ready` and
    /// recomputes the next alarm before every park, so latching the wake
    /// state would only force one spurious empty iteration (and possibly an
    /// extra `io_uring_enter`) per wake.
    pub(super) fn unpark_foreign(&self) {
        if thread::current().id() != self.owner {
            self.unpark.wake();
        }
    }

    /// Take the root task's readiness.
    pub(super) fn take_root_ready(&self) -> bool {
        self.root_ready.swap(false, Ordering::Acquire)
    }

    /// Drain all ready tasks.
    pub(super) fn drain(&self) -> Vec<Arc<dyn Erased>> {
        let mut queue = self.ready.lock();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    /// Whether any task (including the root) is ready to be polled.
    pub(super) fn has_ready(&self) -> bool {
        self.root_ready.load(Ordering::Acquire) || !self.ready.lock().is_empty()
    }

    /// Free a completed task's arena slot.
    pub(super) fn remove(&self, slot: usize) {
        let mut running = self.running.lock();
        if running.closed {
            return;
        }
        running.slots[slot] = None;
        running.free.push(slot);
    }

    /// Clear all tasks and reject future registrations.
    pub(super) fn clear(&self) -> Vec<Arc<dyn Erased>> {
        // Clear ready
        self.ready.lock().clear();

        // Clear running tasks and close the arena so registrations racing
        // teardown are rejected rather than leaked.
        let slots = {
            let mut running = self.running.lock();
            running.closed = true;
            running.free.clear();
            take(&mut running.slots)
        };
        slots.into_iter().flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{super::Runner, *};
    use crate::{Clock as _, Runner as _, Spawner as _, Supervisor as _};
    use commonware_utils::channel::oneshot;
    use std::{task::Waker, time::Duration};

    /// Repeated wakes of the same task before its next poll must coalesce
    /// into one ready-queue entry: unguarded pushes let a legal
    /// multiple-wakes-per-poll future grow the queue without bound.
    #[test]
    fn test_duplicate_wakes_coalesce() {
        Runner::default().start(|context| async move {
            let executor = context.executor.upgrade().unwrap();

            // Smuggle a spawned task's waker out through a oneshot.
            let (send, recv) = oneshot::channel();
            let _task = context.child("waker").spawn(move |_| async move {
                let mut send = Some(send);
                std::future::poll_fn(move |cx| {
                    if let Some(send) = send.take() {
                        let _ = send.send(cx.waker().clone());
                    }
                    Poll::<()>::Pending
                })
                .await
            });
            let waker = recv.await.unwrap();

            // The task was polled (it sent the waker) and is idle: repeated
            // wakes must queue it exactly once.
            let before = executor.tasks.ready.lock().len();
            for _ in 0..5 {
                waker.wake_by_ref();
            }
            let after = executor.tasks.ready.lock().len();
            assert_eq!(after - before, 1, "duplicate wakes must coalesce");
        });
    }

    /// A task that wakes itself multiple times per poll (by ref and by
    /// value) must complete exactly once, and any queue entries polled after
    /// completion must be inert: arena slots freed at completion are
    /// immediately reused by later spawns.
    #[test]
    // The by-value wake is deliberate: it exercises the consuming waker
    // vtable path alongside `wake_by_ref`.
    #[allow(clippy::waker_clone_wake)]
    fn test_self_wake_storm_and_slot_reuse() {
        struct SelfWakeStorm {
            polls: usize,
        }
        impl Future for SelfWakeStorm {
            type Output = usize;
            fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<usize> {
                self.polls += 1;
                if self.polls >= 4 {
                    return Poll::Ready(self.polls);
                }
                cx.waker().wake_by_ref();
                cx.waker().wake_by_ref();
                cx.waker().clone().wake();
                Poll::Pending
            }
        }

        Runner::default().start(|context| async move {
            let storm = context.child("storm").spawn(|_| SelfWakeStorm { polls: 0 });
            assert_eq!(storm.await.unwrap(), 4);

            // Stale queued pointers from the storm must not have freed or
            // corrupted the reused slots.
            for i in 0..32u32 {
                let handle = context.child("reuse").spawn(move |_| async move { i });
                assert_eq!(handle.await.unwrap(), i);
            }
        });
    }

    /// A waker captured from a completed task must be inert: waking it (from
    /// the runtime thread and from a foreign thread) after its arena slot was
    /// freed and reused must neither double-free the slot nor disturb the
    /// tasks that reused it.
    #[test]
    fn test_stale_waker_after_completion_and_slot_reuse() {
        struct CaptureWaker(Arc<Mutex<Option<Waker>>>);
        impl Future for CaptureWaker {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
                *self.0.lock() = Some(cx.waker().clone());
                Poll::Ready(())
            }
        }

        Runner::default().start(|context| async move {
            let slot = Arc::new(Mutex::new(None));
            let captured = Arc::clone(&slot);
            context
                .child("victim")
                .spawn(move |_| CaptureWaker(captured))
                .await
                .unwrap();

            // The victim completed and freed its slot. Fire the stale waker
            // repeatedly (cross-thread too) while replacements reuse it.
            let waker = slot.lock().take().unwrap();
            waker.wake_by_ref();
            let cross = waker.clone();
            std::thread::spawn(move || cross.wake()).join().unwrap();
            for i in 0..8u32 {
                let handle = context.child("reuse").spawn(move |_| async move { i });
                assert_eq!(handle.await.unwrap(), i);
                waker.wake_by_ref();
            }
        });
    }

    /// A waker that outlives the runtime must be inert: waking and dropping
    /// it after `start` returned must not touch freed executor state.
    #[test]
    // The by-value wake is deliberate: it exercises the consuming waker
    // vtable path alongside `wake_by_ref`.
    #[allow(clippy::waker_clone_wake)]
    fn test_waker_outlives_runtime() {
        struct CaptureWaker(Arc<Mutex<Option<Waker>>>);
        impl Future for CaptureWaker {
            type Output = ();
            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
                *self.0.lock() = Some(cx.waker().clone());
                Poll::Ready(())
            }
        }

        let slot = Arc::new(Mutex::new(None::<Waker>));
        let captured = Arc::clone(&slot);
        Runner::default().start(|context| async move {
            context
                .child("victim")
                .spawn(move |_| CaptureWaker(captured))
                .await
                .unwrap();
        });

        let waker = slot.lock().take().unwrap();
        waker.wake_by_ref();
        waker.clone().wake();
        drop(waker);
    }

    /// Spawns registered from a dedicated worker onto a worker that is
    /// concurrently tearing down must either run or resolve with
    /// [Error::Closed], and never hang, panic, or leave a task polled after
    /// teardown.
    #[test]
    fn test_cross_worker_spawn_races_teardown() {
        for _ in 0..8 {
            Runner::default().start(|context| async move {
                let root_spawner = context.child("target");
                let (entered_send, entered_recv) = oneshot::channel();
                let _dedicated = context.child("ded").dedicated().spawn(move |_| async move {
                    // Register onto the root worker from this thread
                    // while the root races into teardown.
                    let mut entered = Some(entered_send);
                    for i in 0..1024u32 {
                        let handle = root_spawner.child("race").spawn(move |_| async move { i });
                        // Prove the loop started (first spawn issued) before
                        // the root is allowed to tear down.
                        if let Some(entered) = entered.take() {
                            let _ = entered.send(());
                        }
                        match handle.await {
                            Ok(value) => assert_eq!(value, i),
                            Err(Error::Closed) => break,
                            Err(err) => panic!("unexpected spawn error: {err}"),
                        }
                    }
                });
                // Return as soon as the dedicated worker has provably entered
                // its spawn loop: teardown races the remaining spawns.
                let _ = entered_recv.await;
            });
        }
    }

    /// A context moved to a raw thread can spawn a task back onto its origin
    /// worker: the task cell is pinned to the worker that polls it, not to
    /// the registering thread.
    #[test]
    fn test_spawn_from_foreign_thread() {
        Runner::default().start(|context| async move {
            let (send, recv) = oneshot::channel();
            let spawner = context.child("foreign");
            std::thread::spawn(move || {
                let handle = spawner.spawn(|context| async move {
                    context.sleep(Duration::from_millis(10)).await;
                    42
                });
                let _ = send.send(handle);
            });
            assert_eq!(recv.await.unwrap().await.unwrap(), 42);
        });
    }

    /// A dedicated task can spawn onto another worker through a moved
    /// context, and the spawned task runs on the context's origin worker.
    #[test]
    fn test_cross_worker_spawn() {
        Runner::default().start(|context| async move {
            let root_spawner = context.child("sibling");
            let dedicated = context
                .child("dedicated")
                .dedicated()
                .spawn(move |_| async move {
                    // Register onto the root worker from this worker's
                    // thread, then await the result across threads.
                    root_spawner.spawn(|_| async move { 7 }).await.unwrap()
                });
            assert_eq!(dedicated.await.unwrap(), 7);
        });
    }

    /// Property: a cleared arena rejects registration and drops the supplied
    /// future without polling it. Setup: create [Tasks] directly and close
    /// the arena with [Tasks::clear]. Action: register a future holding a
    /// drop probe, then perform a late remove. Expected: register returns
    /// false, the probe reports the future dropped unpolled, and the late
    /// remove is harmless.
    #[test]
    fn test_clear_rejects_registration_and_drops_future() {
        struct Probe {
            polled: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }
        impl Future for Probe {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<()> {
                self.polled.store(true, Ordering::Release);
                Poll::Ready(())
            }
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.clear().is_empty());

        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let future = Probe {
            polled: Arc::clone(&polled),
            dropped: Arc::clone(&dropped),
        };
        assert!(
            !Tasks::register(&tasks, future),
            "closed arena must reject registration"
        );
        assert!(dropped.load(Ordering::Acquire), "future must drop unpolled");
        assert!(!polled.load(Ordering::Acquire), "future must not be polled");

        // A late remove after clear is harmless.
        tasks.remove(0);
    }
}
