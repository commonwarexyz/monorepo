//! Task machinery for the io_uring runtime executor.
//!
//! A spawned task is one [TaskCell] allocation: the concrete future stored
//! inline, the identity behind an `ArcWake` waker sharing that allocation,
//! and a queued latch that coalesces repeated wakes into one ready-lane
//! entry. Polling crosses a single type-erased boundary ([Erased]) so the
//! compiler sees the concrete future type inside the monomorphized cell.
//! [Tasks] owns normal and event-ready FIFO lanes plus the arena of running
//! tasks. Initial polls, task self-wakes, and foreign-thread wakes use the
//! normal lane. A first wake delivered by the owner during an explicit event
//! phase uses the event lane so bounded executor turns can promptly poll I/O
//! and timer consumers without starving the normal backlog. Completed slots
//! are recycled for later spawns, and futures stay pinned to the worker
//! thread that polls them ([Affine]) while registration and wakes may arrive
//! from any thread. Teardown clears the arena and both lanes, and rejects
//! racing registrations instead of leaking tasks nothing will ever poll.

// In scope for the intra-doc links in this module's documentation.
#[allow(unused_imports)]
use super::Executor;
use super::capture_cleanup_panic;
use crate::iouring::driver::{Affine, current_thread_id, waker::Waker as RingWaker};
#[allow(unused_imports)]
use crate::{Error, Handle};
use commonware_utils::sync::Mutex;
use futures::task::{ArcWake, waker, waker_ref};
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
pub(super) trait Erased: Send + Sync {
    /// Poll the stored future, returning its arena slot only when this call
    /// completed it (the caller then frees that slot).
    ///
    /// A pending future or stale token for an already-cleared future returns
    /// `None`.
    fn poll(self: Arc<Self>) -> Option<usize>;

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
    /// Whether the task is already in a ready lane (or terminally done).
    ///
    /// A waker may legally fire many times before its task is polled, and
    /// each unguarded push is a full re-poll (a future waking itself twice per
    /// poll would double the queue every executor turn). Only the wake that
    /// transitions this latch selects and enters a lane, and the rest
    /// coalesce. This also prevents an event wake from promoting a normal
    /// token already queued. The latch is released immediately before polling
    /// a live future and set terminally once the future is gone, so late wakes
    /// on a completed or cleared cell buy at most one dead poll.
    queued: AtomicBool,
    /// The future, polled and cleared only on the owning worker thread (a
    /// spawning thread builds the cell but never touches the future), so no
    /// lock is needed.
    ///
    /// `None` once the future completed or teardown cleared it.
    future: Affine<RefCell<Option<F>>>,
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
            // Publish only after winning the queued-latch transition. A
            // coalesced wake above cannot move an existing token.
            tasks.queue_wake(Arc::clone(self) as Arc<dyn Erased>);
        }
    }
}

impl<F> ArcWake for TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.enqueue();
    }
}

impl<F> Erased for TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn poll(self: Arc<Self>) -> Option<usize> {
        // Borrow the task allocation while polling. Futures that retain the
        // waker still clone it into an owned `ArcWake` waker as usual.
        let waker = waker_ref(&self);
        let mut cx = task::Context::from_waker(&waker);
        self.future.with(|cell| {
            let mut slot = cell.borrow_mut();
            // A wake that raced completion may re-poll a dead cell: its slot
            // was already freed, so report no completion. The queued latch
            // stays set (the wake that scheduled this poll set it), so later
            // wakes cannot re-queue the cell again.
            let future = slot.as_mut()?;
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
                    Some(self.slot)
                }
                Poll::Pending => None,
            }
        })
    }

    fn clear(&self) {
        // Terminal latch first: teardown-era late wakes must not re-queue a
        // cell nothing will poll again.
        self.queued.store(true, Ordering::Relaxed);
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
    slots: Vec<Option<Arc<dyn Erased>>>,
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
    normal: VecDeque<Arc<dyn Erased>>,
    /// Event-delivered readiness in arrival order.
    event: VecDeque<Arc<dyn Erased>>,
}

/// Move exactly `count` tokens from the front of `lane` into `scratch`.
///
/// Callers cap `count` to the lane length before entering this hot loop.
#[inline]
fn drain_front(
    lane: &mut VecDeque<Arc<dyn Erased>>,
    scratch: &mut Vec<Arc<dyn Erased>>,
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
        arc_self.queue_normal(cell as Arc<dyn Erased>);
        true
    }

    /// Enqueue a task's initial poll at the back of the normal lane.
    fn queue_normal(&self, task: Arc<dyn Erased>) {
        self.ready.lock().normal.push_back(task);
        self.unpark_foreign();
    }

    /// Classify and enqueue a wake that won its task's queued latch.
    ///
    /// One current-thread lookup determines both event eligibility and
    /// whether the ring needs a foreign wake. Only an owner-thread wake inside
    /// an event-delivery phase enters the event lane. Foreign wakes remain
    /// normal even if they race such a phase, and task self-wakes remain
    /// normal because task polling is outside it.
    fn queue_wake(&self, task: Arc<dyn Erased>) {
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
        scratch: &mut Vec<Arc<dyn Erased>>,
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
        // Detach both ready lanes so Arc destruction runs outside their lock.
        let (normal, event) = {
            let mut ready = self.ready.lock();
            (
                std::mem::take(&mut ready.normal),
                std::mem::take(&mut ready.event),
            )
        };

        // Close and detach the arena before invoking task destructors so
        // racing registrations are rejected and every callback runs outside
        // the arena lock.
        let slots = self
            .running
            .lock()
            .take()
            .map(|running| running.slots)
            .unwrap_or_default();

        let mut first_panic = None;
        for task in normal.into_iter().chain(event) {
            capture_cleanup_panic(&mut first_panic, move || drop(task));
        }
        for task in slots.into_iter().flatten() {
            capture_cleanup_panic(&mut first_panic, || task.clear());
            capture_cleanup_panic(&mut first_panic, move || drop(task));
        }
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
mod tests {
    use super::{
        super::{EVENT_READY_TASKS_PER_TURN, READY_TASKS_PER_TURN, Runner},
        *,
    };
    use crate::{Clock as _, Runner as _, Spawner as _, Supervisor as _};
    use commonware_utils::channel::oneshot;
    use std::{sync::atomic::AtomicUsize, task::Waker, time::Duration};

    /// Build an unregistered pending task cell for ready-lane tests.
    fn pending_cell(
        tasks: &Arc<Tasks>,
        slot: usize,
        queued: bool,
    ) -> Arc<TaskCell<std::future::Pending<()>>> {
        Arc::new(TaskCell {
            slot,
            tasks: Arc::downgrade(tasks),
            queued: AtomicBool::new(queued),
            future: Affine::pinned(
                std::thread::current().id(),
                RefCell::new(Some(std::future::pending())),
            ),
        })
    }

    /// Build an unregistered ready task cell for ready-lane order tests.
    fn ready_cell(tasks: &Arc<Tasks>, slot: usize) -> Arc<TaskCell<std::future::Ready<()>>> {
        Arc::new(TaskCell {
            slot,
            tasks: Arc::downgrade(tasks),
            queued: AtomicBool::new(true),
            future: Affine::pinned(
                std::thread::current().id(),
                RefCell::new(Some(std::future::ready(()))),
            ),
        })
    }

    /// Poll a drained batch of ready tokens and return their completion slots.
    fn completed_slots(tasks: &mut Vec<Arc<dyn Erased>>) -> Vec<usize> {
        tasks
            .drain(..)
            .map(|task| task.poll().expect("ready token must complete"))
            .collect()
    }

    /// Append an unregistered token to one ready lane without unparking.
    fn queue_token(tasks: &Tasks, task: Arc<dyn Erased>, lane: ReadyLane) {
        let mut ready = tasks.ready.lock();
        match lane {
            ReadyLane::Normal => ready.normal.push_back(task),
            ReadyLane::Event => ready.event.push_back(task),
        }
    }

    /// Separately constructed wakers for one task must retain the task's
    /// pointer identity so callers can use `Waker::will_wake`.
    #[test]
    fn test_task_wakers_will_wake_same_cell() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        let cell = Arc::new(TaskCell {
            slot: 0,
            tasks: Arc::downgrade(&tasks),
            queued: AtomicBool::new(true),
            future: Affine::pinned(
                std::thread::current().id(),
                RefCell::new(Some(std::future::pending::<()>())),
            ),
        });

        let first = waker(Arc::clone(&cell));
        let second = waker(Arc::clone(&cell));
        assert!(first.will_wake(&second));
    }

    /// The initial event quota is drained first, a normal token present in the
    /// snapshot is reserved, and unused normal capacity is filled from the
    /// event lane without crossing the combined limit.
    #[test]
    fn test_event_drain_prioritizes_quota_and_reserves_normal() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        for slot in 0..2 {
            queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Normal);
        }
        for slot in 10..14 {
            queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Event);
        }

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 4, 1);
        assert_eq!(scratch.len(), 4);
        assert_eq!(completed_slots(&mut scratch), vec![10, 0, 1, 11]);

        tasks.drain_into(&mut scratch, 4, 1);
        assert_eq!(completed_slots(&mut scratch), vec![12, 13]);
        assert!(!tasks.has_ready());
    }

    #[test]
    fn test_zero_limit_drain_preserves_ready_tokens() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        queue_token(&tasks, ready_cell(&tasks, 0), ReadyLane::Normal);
        queue_token(&tasks, ready_cell(&tasks, 10), ReadyLane::Event);

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 0, 1);
        assert!(scratch.is_empty());
        assert!(tasks.has_ready());
        {
            let ready = tasks.ready.lock();
            assert_eq!(ready.normal.len(), 1);
            assert_eq!(ready.event.len(), 1);
        }

        tasks.drain_into(&mut scratch, 2, 1);
        assert_eq!(completed_slots(&mut scratch), vec![10, 0]);
        assert!(!tasks.has_ready());
    }

    /// Multiple drains may interleave the lanes, but tokens from each lane
    /// retain their own arrival order.
    #[test]
    fn test_ready_lanes_preserve_fifo_order() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        for slot in 0..3 {
            queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Normal);
        }
        for slot in 10..13 {
            queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Event);
        }

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 4, 2);
        assert_eq!(completed_slots(&mut scratch), vec![10, 11, 0, 1]);
        tasks.drain_into(&mut scratch, 4, 2);
        assert_eq!(completed_slots(&mut scratch), vec![12, 2]);
        assert!(!tasks.has_ready());
    }

    /// The production half-turn event quota drains a 64-event burst in two
    /// snapshots while an older normal backlog advances by the other half of
    /// each snapshot. This is the burst-tail and starvation contract selected
    /// by the scheduler benchmark.
    #[test]
    fn test_production_event_quota_balances_burst_and_normal_progress() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        for slot in 0..READY_TASKS_PER_TURN * 2 {
            queue_token(&tasks, ready_cell(&tasks, slot), ReadyLane::Normal);
        }
        for slot in 0..READY_TASKS_PER_TURN {
            queue_token(&tasks, ready_cell(&tasks, 1_000 + slot), ReadyLane::Event);
        }

        let mut scratch = Vec::with_capacity(READY_TASKS_PER_TURN);
        tasks.drain_into(
            &mut scratch,
            READY_TASKS_PER_TURN,
            EVENT_READY_TASKS_PER_TURN,
        );
        assert_eq!(
            completed_slots(&mut scratch),
            (1_000..1_000 + EVENT_READY_TASKS_PER_TURN)
                .chain(0..READY_TASKS_PER_TURN - EVENT_READY_TASKS_PER_TURN)
                .collect::<Vec<_>>()
        );

        tasks.drain_into(
            &mut scratch,
            READY_TASKS_PER_TURN,
            EVENT_READY_TASKS_PER_TURN,
        );
        assert_eq!(
            completed_slots(&mut scratch),
            (1_000 + EVENT_READY_TASKS_PER_TURN..1_000 + READY_TASKS_PER_TURN)
                .chain(
                    READY_TASKS_PER_TURN - EVENT_READY_TASKS_PER_TURN
                        ..2 * (READY_TASKS_PER_TURN - EVENT_READY_TASKS_PER_TURN),
                )
                .collect::<Vec<_>>()
        );

        scratch.clear();
        let ready = tasks.ready.lock();
        assert!(ready.event.is_empty());
        assert_eq!(ready.normal.len(), READY_TASKS_PER_TURN);
    }

    /// An event wake cannot promote a token already latched in the normal
    /// lane because lane selection happens only on the first latch transition.
    #[test]
    fn test_event_wake_does_not_promote_queued_normal_token() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let cell = pending_cell(&tasks, 7, true);
        let task_waker = waker(Arc::clone(&cell));
        queue_token(&tasks, cell as Arc<dyn Erased>, ReadyLane::Normal);

        {
            let _event_delivery = tasks.event_delivery();
            task_waker.wake_by_ref();
        }

        let ready = tasks.ready.lock();
        assert_eq!(ready.normal.len(), 1);
        assert!(ready.event.is_empty());
        drop(ready);
        tasks.clear();
    }

    /// A self-wake published while a spawned task is being polled uses the
    /// normal lane because task polling is outside event-delivery phases.
    #[test]
    fn test_task_poll_self_wake_uses_normal_lane() {
        struct WakePending;

        impl Future for WakePending {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let cell = Arc::new(TaskCell {
            slot: 5,
            tasks: Arc::downgrade(&tasks),
            queued: AtomicBool::new(true),
            future: Affine::pinned(std::thread::current().id(), RefCell::new(Some(WakePending))),
        });
        queue_token(&tasks, cell as Arc<dyn Erased>, ReadyLane::Normal);

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 1, 1);
        assert_eq!(scratch.pop().unwrap().poll(), None);

        let ready = tasks.ready.lock();
        assert_eq!(ready.normal.len(), 1);
        assert!(ready.event.is_empty());
        drop(ready);
        tasks.clear();
    }

    /// A foreign-thread wake remains normal even while the owner holds an
    /// event-delivery guard.
    #[test]
    fn test_foreign_wake_during_event_delivery_uses_normal_lane() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let cell = pending_cell(&tasks, 3, false);
        let task_waker = waker(Arc::clone(&cell));

        {
            let _event_delivery = tasks.event_delivery();
            std::thread::spawn(move || task_waker.wake())
                .join()
                .unwrap();
        }

        let ready = tasks.ready.lock();
        assert_eq!(ready.normal.len(), 1);
        assert!(ready.event.is_empty());
        drop(ready);
        tasks.clear();
    }

    /// Dropping an event-delivery guard during unwinding resets the phase so
    /// the next owner-thread wake returns to the normal lane.
    #[test]
    fn test_event_delivery_phase_resets_after_unwind() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _event_delivery = tasks.event_delivery();
            panic!("event delivery panic");
        }));
        assert!(result.is_err());

        let cell = pending_cell(&tasks, 4, false);
        ArcWake::wake_by_ref(&cell);
        let ready = tasks.ready.lock();
        assert_eq!(ready.normal.len(), 1);
        assert!(ready.event.is_empty());
        drop(ready);
        tasks.clear();
    }

    /// Repeated event wakes before a poll coalesce into one event token.
    #[test]
    fn test_repeated_event_wakes_coalesce() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let cell = pending_cell(&tasks, 6, false);

        {
            let _event_delivery = tasks.event_delivery();
            for _ in 0..5 {
                ArcWake::wake_by_ref(&cell);
            }
        }

        let ready = tasks.ready.lock();
        assert!(ready.normal.is_empty());
        assert_eq!(ready.event.len(), 1);
        drop(ready);
        tasks.clear();
    }

    /// An event token made stale by completion still consumes its batch slot,
    /// leaving one of two normal tokens for the next drain.
    #[test]
    fn test_stale_event_completion_consumes_batch_budget() {
        struct WakeThenReady;

        impl Future for WakeThenReady {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
                cx.waker().wake_by_ref();
                Poll::Ready(())
            }
        }

        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        let completing = Arc::new(TaskCell {
            slot: 8,
            tasks: Arc::downgrade(&tasks),
            queued: AtomicBool::new(true),
            future: Affine::pinned(
                std::thread::current().id(),
                RefCell::new(Some(WakeThenReady)),
            ),
        });
        queue_token(&tasks, completing as Arc<dyn Erased>, ReadyLane::Normal);

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 1, 1);
        let completing_token = scratch.pop().unwrap();
        {
            let _event_delivery = tasks.event_delivery();
            assert_eq!(completing_token.poll(), Some(8));
        }
        queue_token(&tasks, ready_cell(&tasks, 9), ReadyLane::Normal);
        queue_token(&tasks, ready_cell(&tasks, 10), ReadyLane::Normal);

        tasks.drain_into(&mut scratch, 2, 1);
        let stale = scratch.remove(0);
        assert_eq!(stale.poll(), None);
        assert_eq!(completed_slots(&mut scratch), vec![9]);
        let ready = tasks.ready.lock();
        assert_eq!(ready.normal.len(), 1);
        assert!(ready.event.is_empty());
        drop(ready);
        tasks.clear();
    }

    /// Teardown clears both spawned-task lanes and removes their readiness.
    #[test]
    fn test_clear_covers_both_ready_lanes() {
        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        queue_token(&tasks, pending_cell(&tasks, 0, true), ReadyLane::Normal);
        queue_token(&tasks, pending_cell(&tasks, 1, true), ReadyLane::Event);
        assert!(tasks.has_ready());

        tasks.clear();
        let ready = tasks.ready.lock();
        assert!(ready.normal.is_empty());
        assert!(ready.event.is_empty());
        drop(ready);
        assert!(!tasks.has_ready());
    }

    /// A panic from one task destructor must not skip later task destructors,
    /// and the earliest payload remains the one propagated by teardown.
    #[test]
    fn test_clear_continues_after_multiple_task_drop_panics() {
        struct PanicOnDrop {
            message: &'static str,
            drops: Arc<AtomicUsize>,
        }

        impl Future for PanicOnDrop {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }

        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::AcqRel);
                panic!("{}", self.message);
            }
        }

        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        let drops = Arc::new(AtomicUsize::new(0));
        assert!(Tasks::register(
            &tasks,
            PanicOnDrop {
                message: "first task drop panic",
                drops: Arc::clone(&drops),
            }
        ));
        assert!(Tasks::register(
            &tasks,
            PanicOnDrop {
                message: "second task drop panic",
                drops: Arc::clone(&drops),
            }
        ));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tasks.clear()));
        let payload = result.expect_err("task teardown should propagate the first panic");
        assert_eq!(
            payload.downcast_ref::<String>().map(String::as_str),
            Some("first task drop panic")
        );
        assert_eq!(drops.load(Ordering::Acquire), 2);
    }

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
            let before = {
                let ready = executor.tasks.ready.lock();
                ready.normal.len() + ready.event.len()
            };
            for _ in 0..5 {
                waker.wake_by_ref();
            }
            let after = {
                let ready = executor.tasks.ready.lock();
                ready.normal.len() + ready.event.len()
            };
            assert_eq!(after - before, 1, "duplicate wakes must coalesce");
        });
    }

    /// A bounded drain preserves FIFO order and leaves every token beyond the
    /// limit in the shared queue, where [Tasks::has_ready] keeps the worker
    /// from parking. A second drain observes the remainder without loss.
    #[test]
    fn test_bounded_fifo_drain_is_lossless_and_remains_ready() {
        const LIMIT: usize = 64;

        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        for _ in 0..=LIMIT {
            assert!(Tasks::register(&tasks, std::future::ready(())));
        }

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, LIMIT, 1);
        assert_eq!(scratch.len(), LIMIT);
        let first = completed_slots(&mut scratch);
        assert_eq!(first, (0..LIMIT).collect::<Vec<_>>());
        for slot in first {
            tasks.remove(slot);
        }
        assert_eq!(tasks.ready.lock().normal.len(), 1);
        assert!(tasks.has_ready(), "shared remainder must prevent parking");

        tasks.drain_into(&mut scratch, LIMIT, 1);
        assert_eq!(scratch.len(), 1);
        assert_eq!(completed_slots(&mut scratch), vec![LIMIT]);
        tasks.remove(LIMIT);
        assert!(!tasks.has_ready());

        tasks.clear();
    }

    /// A task can wake itself and then complete, leaving one stale token in
    /// the ready queue. That token consumes a bounded-drain slot and remains
    /// inert, while a replacement reusing the same arena slot stays queued
    /// for the next drain.
    #[test]
    fn test_stale_self_wake_consumes_batch_budget() {
        struct WakeThenReady;

        impl Future for WakeThenReady {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<()> {
                cx.waker().wake_by_ref();
                Poll::Ready(())
            }
        }

        let tasks = Arc::new(Tasks::new(RingWaker::new().expect("wake eventfd")));
        assert!(tasks.take_root_ready());
        assert!(Tasks::register(&tasks, WakeThenReady));

        let mut scratch = Vec::new();
        tasks.drain_into(&mut scratch, 1, 1);
        let task = scratch.pop().unwrap();
        let slot = task.poll().expect("live task must complete");
        tasks.remove(slot);

        // The self-wake token precedes this replacement in FIFO order, and
        // the completed task's arena slot is immediately reused.
        assert!(Tasks::register(&tasks, std::future::ready(())));
        assert_eq!(tasks.ready.lock().normal.len(), 2);

        tasks.drain_into(&mut scratch, 1, 1);
        let stale = scratch.pop().unwrap();
        assert_eq!(stale.poll(), None, "completed self-wake must be inert");
        assert_eq!(tasks.ready.lock().normal.len(), 1);
        assert!(tasks.has_ready(), "replacement must remain ready");

        tasks.drain_into(&mut scratch, 1, 1);
        let replacement = scratch.pop().unwrap();
        assert_eq!(replacement.poll(), Some(slot));
        tasks.remove(slot);
        assert!(!tasks.has_ready());
        tasks.clear();
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

    #[test]
    #[allow(clippy::waker_clone_wake)]
    fn test_root_waker_outlives_runtime() {
        let slot = Arc::new(Mutex::new(None::<Waker>));
        let captured = Arc::clone(&slot);
        let task_slot = Arc::new(Mutex::new(None::<std::sync::Weak<Tasks>>));
        let captured_tasks = Arc::clone(&task_slot);
        Runner::default().start(move |context| {
            let executor = context.executor.upgrade().unwrap();
            *captured_tasks.lock() = Some(Arc::downgrade(&executor.tasks));
            std::future::poll_fn(move |cx| {
                *captured.lock() = Some(cx.waker().clone());
                Poll::Ready(())
            })
        });

        // The retained waker must not keep the task arena or ring wake fd alive.
        assert!(task_slot.lock().take().unwrap().upgrade().is_none());
        let waker = slot.lock().take().unwrap();
        waker.wake_by_ref();
        waker.clone().wake();
        drop(waker);
    }

    /// Spawns registered from a dedicated worker onto a worker that is
    /// paused immediately before registration must be rejected when the
    /// target worker closes its arena in the interim.
    #[test]
    fn test_cross_worker_spawn_rejected_after_arena_closes() {
        let polled = Arc::new(AtomicBool::new(false));
        let polled_by_task = Arc::clone(&polled);
        let (result_send, result_recv) = std::sync::mpsc::channel();

        Runner::default().start(move |context| async move {
            let tasks = context.executor().tasks.clone();
            let target = context.child("target");
            let (paused_send, paused_recv) = oneshot::channel();
            let observed_tasks = Arc::downgrade(&tasks);
            tasks.hook_register_once(move || {
                paused_send
                    .send(())
                    .expect("root worker dropped pause signal");
                let tasks = observed_tasks
                    .upgrade()
                    .expect("task arena dropped during registration");
                while !tasks.is_closed() {
                    std::thread::yield_now();
                }
            });

            let _dedicated = context
                .child("dedicated")
                .dedicated()
                .spawn(move |_| async move {
                    let handle = target.spawn(move |_| {
                        std::future::poll_fn(move |_| {
                            polled_by_task.store(true, Ordering::Release);
                            Poll::Ready(())
                        })
                    });
                    let result = handle.await;
                    result_send
                        .send(result)
                        .expect("test dropped spawn result receiver");
                });

            paused_recv.await.expect("registration did not reach hook");
        });

        let result = result_recv.recv().expect("dedicated worker dropped");
        assert!(
            matches!(&result, Err(Error::Closed)),
            "spawn returned an unexpected result: {result:?}"
        );
        assert!(
            !polled.load(Ordering::Acquire),
            "rejected task must not be polled"
        );
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
        tasks.clear();

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
