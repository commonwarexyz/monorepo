//! Task machinery for the io_uring runtime executor.
//!
//! A spawned task is one [TaskCell] allocation: the concrete future stored
//! inline, the identity behind an `ArcWake` waker sharing that allocation,
//! and a compact state machine that coalesces repeated wakes into one ready-lane
//! entry. A notification received while polling is queued only if that poll
//! returns `Pending`, so wake-then-complete futures leave no stale token.
//! Polling crosses a single type-erased boundary ([ErasedTask]) so the
//! compiler sees the concrete future type inside the monomorphized cell.
//! [Tasks] owns normal and event-ready FIFO lanes plus the arena of running
//! tasks. Initial polls, task self-wakes, and foreign-thread wakes use the
//! normal lane. A first wake delivered by the owner during an explicit event
//! phase uses the event lane so bounded executor turns can promptly poll I/O
//! and timer consumers without starving the normal backlog. Completed slots
//! are recycled for later spawns, and futures stay pinned to the worker
//! thread that polls them ([Affine]) while registration and wakes may arrive
//! from any thread. Teardown closes registration, detaches the arena and the
//! current contents of both lanes, and clears every admitted task. A
//! registration that inserted its cell before closure may append a still-queued
//! token to the newly empty normal lane after its previous contents were
//! detached. That token is harmless because the worker never polls either lane
//! after entering teardown, and clearing the captured cell still completes the
//! task.

// In scope for the intra-doc links in this module's documentation.
#[allow(unused_imports)]
use super::Executor;
use super::capture_cleanup_panic;
use crate::iouring::driver::{Affine, RingWaker, current_thread_id};
#[allow(unused_imports)]
use crate::{Error, Handle};
use commonware_utils::sync::Mutex;
use futures::task::{ArcWake, waker, waker_ref};
#[cfg(feature = "loom")]
use loom::sync::atomic::AtomicU8;
#[cfg(not(feature = "loom"))]
use std::sync::atomic::AtomicU8;
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    rc::Rc,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{self, Poll},
    thread::ThreadId,
};

/// Type-erased boundary for a task in the arena.
///
/// The concrete future lives inline in the task's single `Arc` allocation,
/// so the only dynamic dispatch on the poll path is this trait: inside the
/// monomorphized [TaskCell] methods the compiler sees the concrete future
/// type end to end.
pub(super) trait ErasedTask: Send + Sync {
    /// Poll the stored future, returning its arena slot only when this call
    /// completed it (the caller then frees that slot). `tasks` is the owner
    /// that supplied this ready token and receives any deferred self-wake.
    ///
    /// A pending future or stale token for an already-cleared future returns
    /// `None`.
    fn poll(self: Arc<Self>, tasks: &Tasks) -> Option<usize>;

    /// Resolve the task without polling: drop the future in place (which
    /// resolves any join handle with [Error::Closed]).
    fn clear(&self);
}

/// A spawned task: one allocation holding the concrete future and the
/// identity behind its `ArcWake` waker. Results reach the task's handle
/// through the wrapper built by [Handle::init], not through the cell.
struct TaskCell<F>
where
    F: Future<Output = ()>,
{
    /// Arena slot to free at completion.
    slot: usize,
    /// Re-enqueue target for wakes.
    tasks: Weak<Tasks>,
    /// Scheduling state that coalesces wakes and defers notifications received
    /// during a poll until that poll returns `Pending`.
    state: TaskState,
    /// The future, polled and cleared only on the owning worker thread (a
    /// spawning thread builds the cell but never touches the future), so no
    /// lock is needed.
    ///
    /// `None` once the future completed or teardown cleared it.
    future: Affine<RefCell<Option<F>>>,
}

/// Task is dormant and has no ready token.
const TASK_IDLE: u8 = 0;
/// One ready token owns the right to poll the task.
const TASK_QUEUED: u8 = 1;
/// The owner worker is currently polling the task.
const TASK_RUNNING: u8 = 2;
/// A wake arrived while the owner worker was polling the task.
const TASK_NOTIFIED: u8 = 3;
/// The future completed or teardown cleared it.
const TASK_COMPLETE: u8 = 4;

/// Atomic scheduling state for one task.
///
/// The ready queue owns the task while it is `QUEUED`. Polling changes that
/// state to `RUNNING`. A concurrent wake changes `RUNNING` to `NOTIFIED`
/// without adding a token. The polling thread publishes the successor token
/// only after observing `Pending`, or discards the notification after
/// `Ready`. `COMPLETE` is terminal and also covers teardown.
struct TaskState(
    /// Current `TASK_*` state, synchronized with ready-token publication.
    AtomicU8,
);

impl TaskState {
    /// Build a state for a task whose first poll is already queued.
    // Loom's AtomicU8 constructor is not const, so this definition must remain
    // usable with both atomic backends.
    #[allow(clippy::missing_const_for_fn)]
    fn queued() -> Self {
        Self(AtomicU8::new(TASK_QUEUED))
    }

    /// Build an idle state for tests that exercise wake-driven admission.
    #[cfg(test)]
    // Loom's AtomicU8 constructor is not const, so this definition must remain
    // usable with both atomic backends.
    #[allow(clippy::missing_const_for_fn)]
    fn idle() -> Self {
        Self(AtomicU8::new(TASK_IDLE))
    }

    /// Record a wake, returning true only when the caller must publish a new
    /// ready token.
    fn notify(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, publish) = match state {
                TASK_IDLE => (TASK_QUEUED, true),
                // A same-value RMW publishes changes made before a coalesced
                // wake to the poller's acquiring QUEUED -> RUNNING transition.
                TASK_QUEUED => (TASK_QUEUED, false),
                TASK_RUNNING => (TASK_NOTIFIED, false),
                TASK_NOTIFIED => (TASK_NOTIFIED, false),
                TASK_COMPLETE => return false,
                _ => unreachable!("invalid task state: {state}"),
            };
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return publish,
                Err(actual) => state = actual,
            }
        }
    }

    /// Claim a queued token for polling.
    fn start_poll(&self) -> bool {
        self.0
            .compare_exchange(
                TASK_QUEUED,
                TASK_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Finish a pending poll, returning true when a wake received during the
    /// poll must now be published.
    fn finish_pending(&self) -> bool {
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let (next, publish) = match state {
                TASK_RUNNING => (TASK_IDLE, false),
                TASK_NOTIFIED => (TASK_QUEUED, true),
                TASK_COMPLETE => return false,
                _ => unreachable!("task left poll in invalid state: {state}"),
            };
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return publish,
                Err(actual) => state = actual,
            }
        }
    }

    /// Mark a successfully polled task terminal, discarding any notification
    /// received during its final poll.
    fn complete(&self) {
        let previous = self.0.swap(TASK_COMPLETE, Ordering::AcqRel);
        debug_assert!(matches!(previous, TASK_RUNNING | TASK_NOTIFIED));
    }

    /// Mark a task terminal before teardown drops its future.
    fn clear(&self) {
        self.0.swap(TASK_COMPLETE, Ordering::AcqRel);
    }
}

/// Mark a pinned future slot empty after its in-place drop glue finishes,
/// including when that drop glue unwinds.
struct MarkCleared<F>(*mut Option<F>);

impl<F> Drop for MarkCleared<F> {
    fn drop(&mut self) {
        // SAFETY: the pointer comes from the exclusive RefCell borrow held by
        // TaskCell::clear. The pinned value's drop glue has completed or is
        // unwinding, so writing None without reading or dropping the old
        // representation cannot move the value and prevents a second drop.
        unsafe { self.0.write(None) };
    }
}

impl<F> TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    /// Publish a by-reference wake that changed an idle task to queued.
    ///
    /// If the upgrade fails, the runtime already exited and the wake is a
    /// no-op (e.g. data holding a waker dropped after `start` returned).
    fn notify_by_ref(self: &Arc<Self>) {
        if !self.state.notify() {
            return;
        }
        if let Some(tasks) = self.tasks.upgrade() {
            tasks.queue_wake(Arc::clone(self) as Arc<dyn ErasedTask>);
        }
    }

    /// Publish a by-value wake without cloning the waker's task reference.
    fn notify_by_val(self: Arc<Self>) {
        if !self.state.notify() {
            return;
        }
        let Some(tasks) = self.tasks.upgrade() else {
            return;
        };
        tasks.queue_wake(self as Arc<dyn ErasedTask>);
    }

    /// Publish the notification retained during a poll that returned
    /// `Pending`, transferring the ready token already owned by that poll.
    fn queue_after_pending(self: Arc<Self>, tasks: &Tasks) {
        // A notification received while the task was running always belongs
        // to the normal lane. Event delivery cannot poll tasks, and a direct
        // unit-test event guard must not change this handoff's classification.
        tasks.queue_normal(self as Arc<dyn ErasedTask>);
    }
}

impl<F> ArcWake for TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn wake(self: Arc<Self>) {
        self.notify_by_val();
    }

    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.notify_by_ref();
    }
}

impl<F> ErasedTask for TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn poll(self: Arc<Self>, tasks: &Tasks) -> Option<usize> {
        debug_assert!(
            std::ptr::eq(tasks, self.tasks.as_ptr()),
            "task polled by non-owner"
        );
        // A token racing teardown or completion is inert. Normal operation
        // has exactly one token for each QUEUED state.
        if !self.state.start_poll() {
            return None;
        }

        // Borrow the task allocation while polling. Futures that retain the
        // waker still clone it into an owned `ArcWake` waker as usual.
        let result = {
            let waker = waker_ref(&self);
            let mut cx = task::Context::from_waker(&waker);
            self.future.with(|cell| {
                let mut slot = cell.borrow_mut();
                let future = slot.as_mut().expect("queued task must retain its future");
                // SAFETY: the future lives inside this task's Arc allocation
                // and is never moved out of it: completion (below) and
                // teardown ([ErasedTask::clear]) both drop it in place by
                // overwriting the option with None.
                let future = unsafe { Pin::new_unchecked(future) };
                match future.poll(&mut cx) {
                    Poll::Ready(()) => {
                        // Publish the terminal state before user drop glue
                        // runs. A destructor may wake this task or panic, and
                        // either path must observe a completed cell.
                        self.state.complete();
                        *slot = None;
                        Some(self.slot)
                    }
                    Poll::Pending => None,
                }
            })
        };

        if result.is_none() && self.state.finish_pending() {
            self.queue_after_pending(tasks);
        }
        result
    }

    fn clear(&self) {
        // Terminal state first: teardown-era late wakes must not re-queue a
        // cell nothing will poll again.
        self.state.clear();
        self.future.with(|cell| {
            let mut slot = cell.borrow_mut();
            let Some(future) = slot.as_mut() else {
                return;
            };
            let future = std::ptr::from_mut(future);
            let mark_cleared = MarkCleared(std::ptr::from_mut(&mut *slot));
            // SAFETY: the future is never moved after its TaskCell is pinned.
            // MarkCleared writes None after this pinned in-place drop finishes
            // or unwinds, preventing TaskCell destruction from dropping it a
            // second time.
            unsafe { std::ptr::drop_in_place(future) };
            drop(mark_cleared);
        });
    }
}

/// A waker for the root task, which lives on the runtime thread's stack (so
/// its typed output is captured un-erased) rather than in the arena.
struct RootWaker {
    /// Weak ownership prevents an escaped root waker from retaining the worker.
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

/// The arena of running tasks.
struct Running {
    /// Task slots. Freed slots are recycled through `free`.
    slots: Vec<Option<Arc<dyn ErasedTask>>>,
    /// Recycled slot indices.
    free: Vec<usize>,
}

/// One of the two FIFO lanes for spawned-task ready tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadyLane {
    /// Initial polls, self-wakes, and all foreign-thread wakes.
    Normal,
    /// Owner-thread wakes published during an event-delivery phase.
    Event,
}

/// Spawned-task ready tokens protected by one snapshot lock.
///
/// Keeping both lanes under the same lock lets [Tasks::drain_into] reserve
/// normal service based on one consistent snapshot while preserving FIFO
/// order within each lane.
struct Ready {
    /// Ordinary readiness in arrival order.
    normal: VecDeque<Arc<dyn ErasedTask>>,
    /// Event-delivered readiness in arrival order.
    event: VecDeque<Arc<dyn ErasedTask>>,
}

/// Move exactly `count` tokens from the front of `lane` into `scratch`.
///
/// Callers cap `count` to the lane length before entering this hot loop.
#[inline]
fn drain_front(
    lane: &mut VecDeque<Arc<dyn ErasedTask>>,
    scratch: &mut Vec<Arc<dyn ErasedTask>>,
    count: usize,
) {
    for _ in 0..count {
        scratch.push(lane.pop_front().expect("drain count exceeds lane length"));
    }
}

/// RAII marker for owner-thread event delivery.
///
/// Dropping the marker resets the phase during normal return and unwinding.
/// The marker is not sendable because the phase belongs to [Tasks::owner].
#[must_use = "the event-delivery phase ends when the guard is dropped"]
pub(super) struct EventDelivery<'a> {
    /// Task set whose owner thread is delivering events.
    tasks: &'a Tasks,
    /// Prevents moving the owner-thread phase marker to another thread.
    not_send: PhantomData<Rc<()>>,
}

impl Drop for EventDelivery<'_> {
    fn drop(&mut self) {
        debug_assert_eq!(current_thread_id(), self.tasks.owner);
        self.tasks.delivering_events.store(false, Ordering::Relaxed);
    }
}

/// The tasks being executed by the [Executor].
pub(super) struct Tasks {
    /// Spawned tasks ready to be polled, queued by pointer (no ids or lookups).
    ready: Mutex<Ready>,
    /// Whether the root task is ready to be polled. Starts true for the
    /// kickoff poll.
    root_ready: AtomicBool,
    /// The arena owning all running tasks. `None` after teardown begins.
    running: Mutex<Option<Running>>,
    /// The worker thread that polls (and tears down) these tasks. Task cells
    /// are pinned to it so registration works from any thread.
    owner: ThreadId,
    /// Whether the owner thread is currently delivering driver or timer
    /// events. Only that thread reads true and may select the event lane.
    delivering_events: AtomicBool,
    /// Wakes the runtime thread when a task becomes ready.
    ///
    /// Latches the event loop's out-of-band wake state so a parked executor
    /// (futex or `submit_and_wait`) observes the enqueue from any thread.
    unpark: RingWaker,
    /// One registration boundary callback used by deterministic race tests.
    #[cfg(test)]
    register_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Tasks {
    /// Create a new task queue owned by the calling (worker) thread.
    pub(super) fn new(unpark: RingWaker) -> Self {
        Self {
            ready: Mutex::new(Ready {
                normal: VecDeque::new(),
                event: VecDeque::new(),
            }),
            root_ready: AtomicBool::new(true),
            running: Mutex::new(Some(Running {
                slots: Vec::new(),
                free: Vec::new(),
            })),
            owner: current_thread_id(),
            delivering_events: AtomicBool::new(false),
            unpark,
            #[cfg(test)]
            register_hook: Mutex::new(None),
        }
    }

    /// Enter an event-delivery phase on the owner thread.
    ///
    /// Driver completion callbacks and due-sleeper delivery hold this guard
    /// while invoking task wakers. Event phases must not nest.
    pub(super) fn event_delivery(&self) -> EventDelivery<'_> {
        debug_assert_eq!(current_thread_id(), self.owner);
        debug_assert!(
            !self.delivering_events.load(Ordering::Relaxed),
            "event-delivery phases must not nest"
        );
        self.delivering_events.store(true, Ordering::Relaxed);
        EventDelivery {
            tasks: self,
            not_send: PhantomData,
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
        #[cfg(test)]
        arc_self.run_register_hook();

        let cell = {
            let mut running = arc_self.running.lock();
            let Some(running) = running.as_mut() else {
                return false;
            };
            let slot = running.free.pop().unwrap_or_else(|| {
                running.slots.push(None);
                running.slots.len() - 1
            });
            let cell = Arc::new(TaskCell {
                slot,
                tasks: Arc::downgrade(arc_self),
                state: TaskState::queued(),
                // Pin the cell to the worker that polls it, not to the
                // registering thread: spawns may arrive from any thread
                // through a moved context.
                future: Affine::pinned(arc_self.owner, RefCell::new(Some(future))),
            });
            running.slots[slot] = Some(Arc::clone(&cell) as Arc<dyn ErasedTask>);
            cell
        };

        // Queue the first poll.
        arc_self.queue_normal(cell as Arc<dyn ErasedTask>);
        true
    }

    /// Enqueue an initial poll or deferred running notification at the back
    /// of the normal lane.
    fn queue_normal(&self, task: Arc<dyn ErasedTask>) {
        let mut ready = self.ready.lock();
        ready.normal.push_back(task);
        drop(ready);
        self.unpark_foreign();
    }

    /// Classify and enqueue a wake that changed an idle task to queued.
    ///
    /// One current-thread lookup determines both event eligibility and
    /// whether the ring needs a foreign wake. Only an owner-thread wake inside
    /// an event-delivery phase enters the event lane. Foreign wakes remain
    /// normal even if they race such a phase, and task self-wakes remain
    /// normal because task polling is outside it.
    fn queue_wake(&self, task: Arc<dyn ErasedTask>) {
        let foreign = current_thread_id() != self.owner;
        let lane = if !foreign && self.delivering_events.load(Ordering::Relaxed) {
            ReadyLane::Event
        } else {
            ReadyLane::Normal
        };
        let mut ready = self.ready.lock();
        match lane {
            ReadyLane::Normal => ready.normal.push_back(task),
            ReadyLane::Event => ready.event.push_back(task),
        }
        drop(ready);
        if foreign {
            self.unpark.wake();
        }
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
        if current_thread_id() != self.owner {
            self.unpark.wake();
        }
    }

    /// Take the root task's readiness.
    pub(super) fn take_root_ready(&self) -> bool {
        self.root_ready.swap(false, Ordering::Acquire)
    }

    /// Move up to `limit` spawned-task tokens into `scratch`.
    ///
    /// Up to `event_quota` event tokens come first. If the normal lane was
    /// nonempty at the locked snapshot and `limit` is positive, at least one
    /// normal token is reserved. The normal lane then fills the remaining
    /// capacity, followed by event tokens beyond the quota when capacity is
    /// still unused. Tokens retain FIFO order within each lane. Every moved
    /// token consumes capacity even if polling later finds it stale.
    ///
    /// The caller supplies an empty buffer reused across iterations. Tokens
    /// beyond the combined limit remain shared so [Self::has_ready] prevents
    /// parking, while retained scratch capacity avoids later allocations.
    pub(super) fn drain_into(
        &self,
        scratch: &mut Vec<Arc<dyn ErasedTask>>,
        limit: usize,
        event_quota: usize,
    ) {
        debug_assert!(scratch.is_empty());
        let mut ready = self.ready.lock();
        let normal_reserve = usize::from(limit > 0 && !ready.normal.is_empty());

        // Reserve normal service before taking the prioritized event prefix.
        let event_count = event_quota
            .min(ready.event.len())
            .min(limit.saturating_sub(normal_reserve));
        drain_front(&mut ready.event, scratch, event_count);

        let normal_count = (limit - scratch.len()).min(ready.normal.len());
        drain_front(&mut ready.normal, scratch, normal_count);

        // Fill capacity the normal snapshot could not use. This may exceed
        // the initial event quota but never the combined task limit.
        let event_fill = (limit - scratch.len()).min(ready.event.len());
        drain_front(&mut ready.event, scratch, event_fill);
    }

    /// Whether any task (including the root) is ready to be polled.
    pub(super) fn has_ready(&self) -> bool {
        if self.root_ready.load(Ordering::Acquire) {
            return true;
        }
        let ready = self.ready.lock();
        !ready.normal.is_empty() || !ready.event.is_empty()
    }

    /// Free a completed task's arena slot.
    pub(super) fn remove(&self, slot: usize) {
        let mut running = self.running.lock();
        let Some(running) = running.as_mut() else {
            return;
        };
        running.slots[slot] = None;
        running.free.push(slot);
    }

    /// Clear all tasks and reject future registrations.
    pub(super) fn clear(&self) {
        // Close and detach the arena before dropping futures. A registration
        // that already owns a slot may still publish a harmless ready token,
        // but the cleared task cannot be polled again.
        let slots = self
            .running
            .lock()
            .take()
            .map(|running| running.slots)
            .unwrap_or_default();

        // Detach both lanes atomically with respect to every publisher. Arc
        // destruction runs after releasing the lock.
        let (normal, event) = {
            let mut ready = self.ready.lock();
            (
                std::mem::take(&mut ready.normal),
                std::mem::take(&mut ready.event),
            )
        };

        let mut first_panic = None;
        for task in slots.into_iter().flatten() {
            capture_cleanup_panic(&mut first_panic, || task.clear());
        }
        drop(normal);
        drop(event);
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }
}

#[cfg(test)]
impl Tasks {
    /// Install a callback for the next registration attempt.
    fn hook_register_once(&self, hook: impl FnOnce() + Send + 'static) {
        let mut slot = self.register_hook.lock();
        assert!(slot.is_none(), "registration hook already installed");
        *slot = Some(Box::new(hook));
    }

    /// Run the callback after releasing its slot lock so it may coordinate
    /// with teardown, which needs to acquire other task locks.
    fn run_register_hook(&self) {
        let hook = self.register_hook.lock().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Whether teardown has closed the task arena.
    fn is_closed(&self) -> bool {
        self.running.lock().is_none()
    }
}

#[cfg(test)]
#[path = "task_tests.rs"]
mod tests;

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    //! Exhaustive weak-memory checks for the task notification handoff.

    use super::TaskState;
    use loom::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    /// A wake racing the end of a pending poll transfers exactly one ready
    /// token, regardless of which side wins the atomic handoff.
    #[test]
    fn test_pending_wake_handoff_publishes_once() {
        loom::model(|| {
            let state = Arc::new(TaskState::queued());
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || state.notify()
            });
            let poll_publishes = state.finish_pending();
            let wake_publishes = wake.join().unwrap();

            assert_ne!(poll_publishes, wake_publishes);
            assert!(state.start_poll());
            state.complete();
        });
    }

    /// A wake racing a ready poll is always discarded by the terminal state.
    #[test]
    fn test_ready_wake_handoff_never_publishes() {
        loom::model(|| {
            let state = Arc::new(TaskState::queued());
            assert!(state.start_poll());

            let wake = thread::spawn({
                let state = Arc::clone(&state);
                move || state.notify()
            });
            state.complete();

            assert!(!wake.join().unwrap());
            assert!(!state.notify());
            assert!(!state.start_poll());
        });
    }

    /// Every successful successor claim observes writes published before the
    /// wake, including when the wake coalesces through a same-value RMW.
    #[test]
    fn test_wake_handoff_publishes_payload() {
        loom::model(|| {
            let state = Arc::new(TaskState::queued());
            let payload = Arc::new(AtomicUsize::new(0));

            let producer = thread::spawn({
                let state = Arc::clone(&state);
                let payload = Arc::clone(&payload);
                move || {
                    payload.store(1, Ordering::Relaxed);
                    state.notify();
                }
            });
            let consumer = thread::spawn({
                let state = Arc::clone(&state);
                let payload = Arc::clone(&payload);
                move || {
                    assert!(state.start_poll());
                    if payload.load(Ordering::Acquire) == 1 {
                        state.clear();
                        return;
                    }
                    state.finish_pending();
                    while !state.start_poll() {
                        thread::yield_now();
                    }
                    assert_eq!(payload.load(Ordering::Acquire), 1);
                    state.complete();
                }
            });

            producer.join().unwrap();
            consumer.join().unwrap();
        });
    }
}
