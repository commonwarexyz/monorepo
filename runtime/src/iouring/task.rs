//! Owner-local task cells and FIFO scheduling.
//!
//! The worker owns [`Tasks`]. Foreign threads never access its entries. A task
//! arrives as a concrete wrapped future in one pinned [`Task`] allocation, then
//! crosses a single erased [`Runnable::poll`] boundary on each poll.
//!
//! ```text
//! insert -> Queued -> Running -> Idle
//!              ^         |        |
//!              |      notified    wake
//!              |         |        |
//!              +---------+--------+
//!                        |
//!                      Ready -> Complete -> reusable slot
//! ```
//!
//! The worker takes both the cell and its cached waker before polling. This
//! permits reentrant spawning to grow the arena without invalidating anything
//! used by the poll. Retirement also returns owned values to the worker, so
//! user destructors and waker callbacks run outside the local state borrow.

use super::{
    mailbox::{Mailbox, Message},
    runtime,
    slab::{Id, Slab},
};
use futures::task::{ArcWake, waker};
use std::{
    collections::VecDeque,
    future::Future,
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll, Waker},
};

/// Contain task disposal, independently of the inner user-poll panic policy.
///
/// Abortable can destroy the user future during poll. Both poll and later cell
/// destruction use this boundary outside Local. The caller retires failed IDs
/// before destroying their cells.
pub(super) fn contain<T>(f: impl FnOnce() -> T) -> Option<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(output) => Some(output),
        Err(panic) => {
            // Payload destruction can also run user code. A secondary panic
            // cannot escape this task boundary or replace a worker failure.
            if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(panic))) {
                mem::forget(secondary);
            }
            None
        }
    }
}

/// Root or spawned task selected by an escaped routing waker.
#[derive(Clone, Copy, Debug)]
pub(super) enum Target {
    /// The root future pinned separately on the worker's stack.
    Root,
    /// A generational entry in the local task arena.
    Task(TaskId),
}

/// Safe shared routing state that owns neither a future nor mutable local state.
pub(super) struct Wake {
    /// Weak origin identity, retained even after the worker has shut down.
    mailbox: Weak<Mailbox>,
    /// Root-ready flag or task identity to notify on the owning worker.
    target: Target,
}

impl Wake {
    /// Construct the cached routing waker outside any local borrow.
    pub(super) fn waker(mailbox: Weak<Mailbox>, target: Target) -> Waker {
        waker(Arc::new(Self { mailbox, target }))
    }
}

impl ArcWake for Wake {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        if let Some(local) = runtime::current() {
            let mut local = local.borrow_mut();
            if std::ptr::eq(Arc::as_ptr(&local.mailbox), arc_self.mailbox.as_ptr()) {
                if !local.closing {
                    match arc_self.target {
                        Target::Root if local.root_live => local.root_ready = true,
                        Target::Root => {}
                        Target::Task(id) => local.tasks.wake(id),
                    }
                }
                return;
            }
        }
        if let Some(mailbox) = arc_self.mailbox.upgrade() {
            let _ = mailbox.send(Message::Wake(arc_self.target));
        }
    }
}

/// Register on the origin worker, using direct insertion for a local spawn.
///
/// The caller owns rejected task destruction and runs it outside all borrows.
pub(super) fn register(
    mailbox: &Weak<Mailbox>,
    cell: Pin<Box<dyn Runnable>>,
) -> Result<(), Pin<Box<dyn Runnable>>> {
    if let Some(local) = runtime::current() {
        let id = {
            let state = local.borrow();
            if std::ptr::eq(Arc::as_ptr(&state.mailbox), mailbox.as_ptr()) {
                if state.closing {
                    return Err(cell);
                }
                Some(state.tasks.reserve())
            } else {
                None
            }
        };
        if let Some(id) = id {
            // The routing object performs no user callback during construction.
            // No task registration can interleave with this reserved insertion.
            let waker = Wake::waker(mailbox.clone(), Target::Task(id));
            local.borrow_mut().tasks.insert(id, cell, waker);
            return Ok(());
        }
    }
    let Some(mailbox) = mailbox.upgrade() else {
        return Err(cell);
    };
    match mailbox.send(Message::Spawn(cell)) {
        Ok(()) => Ok(()),
        Err(Message::Spawn(cell)) => Err(cell),
        Err(_) => unreachable!("spawn publication returned another message kind"),
    }
}

/// Full-width identity carried by ready tokens and routing wakers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TaskId(Id);

/// Erased scheduling boundary for an otherwise concrete wrapped future.
pub(super) trait Runnable: Send {
    /// Poll the pinned task on its owning worker.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()>;
}

/// One allocation containing the complete task execution wrapper.
pub(super) struct Task<F> {
    /// Pinned in place with the enclosing cell until destruction.
    future: F,
}

impl<F: Future<Output = ()> + Send + 'static> Task<F> {
    /// Allocate a concrete future before erasing only its scheduling interface.
    pub(super) fn boxed(future: F) -> Pin<Box<dyn Runnable>> {
        Box::pin(Self { future })
    }
}

impl<F: Future<Output = ()> + Send + 'static> Runnable for Task<F> {
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: The pinned Task allocation owns `future`. Neither this type
        // nor its scheduler moves the field after pinning, and destruction runs
        // in place. This projection grants exclusive access only for this poll.
        unsafe { self.map_unchecked_mut(|task| &mut task.future) }.poll(cx)
    }
}

/// Scheduling state changed exclusively by the owning worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum State {
    /// Pending without a notification or ready token.
    Idle,
    /// Exactly one live ready token exists for this entry.
    Queued,
    /// The worker has removed the cell and is polling it.
    Running,
    /// A wake occurred during the current poll.
    Notified,
}

/// One generational slot. A running cell and waker live on the worker's stack.
struct Entry {
    /// Owner-local notification state.
    state: State,
    /// Task allocation when it is not being polled.
    cell: Option<Pin<Box<dyn Runnable>>>,
    /// Routing waker moved out alongside the cell for each poll.
    cached_waker: Option<Waker>,
}

/// Poll-local ownership detached from the arena.
pub(super) struct Running {
    /// Identity used to restore or retire the entry after polling.
    pub(super) id: TaskId,
    /// Pinned concrete task behind its scheduling interface.
    pub(super) cell: Pin<Box<dyn Runnable>>,
    /// Cached waker borrowed during polling without cloning.
    pub(super) waker: Waker,
}

/// Task arena and its single ready lane.
#[derive(Default)]
pub(super) struct Tasks {
    /// Generational slots owned by this worker.
    entries: Slab<Entry>,
    /// FIFO notifications, including harmless stale tokens.
    ready: VecDeque<TaskId>,
}

impl Tasks {
    /// Select an identity before constructing its routing waker outside Local.
    /// No other insertion may occur before the matching `insert` call.
    pub(super) fn reserve(&self) -> TaskId {
        TaskId(self.entries.next_id())
    }

    /// Insert previously selected ownership without invoking any callback.
    pub(super) fn insert(&mut self, id: TaskId, cell: Pin<Box<dyn Runnable>>, waker: Waker) {
        self.entries.insert_at(
            id.0,
            Entry {
                state: State::Queued,
                cell: Some(cell),
                cached_waker: Some(waker),
            },
        );
        self.ready.push_back(id);
    }

    /// Record a notification, coalescing queued and poll-local duplicates.
    pub(super) fn wake(&mut self, id: TaskId) {
        let Some(entry) = self.entries.get_mut(id.0) else {
            return;
        };
        match entry.state {
            State::Idle => {
                entry.state = State::Queued;
                self.ready.push_back(id);
            }
            State::Running => entry.state = State::Notified,
            State::Queued | State::Notified => {}
        }
    }

    /// Consume one token, counting stale tokens toward the caller's budget.
    ///
    /// `None` means this token was stale or the lane was empty. The caller uses
    /// `is_ready` to distinguish an exhausted lane from remaining stale tokens.
    pub(super) fn take(&mut self) -> Option<Running> {
        let id = self.ready.pop_front()?;
        let entry = self.entries.get_mut(id.0)?;
        if entry.state != State::Queued {
            return None;
        }
        entry.state = State::Running;
        Some(Running {
            id,
            cell: entry.cell.take().expect("queued task has a cell"),
            waker: entry.cached_waker.take().expect("queued task has a waker"),
        })
    }

    /// Restore a pending cell, preserving a notification raised during polling.
    pub(super) fn pending(&mut self, task: Running) {
        let entry = self
            .entries
            .get_mut(task.id.0)
            .expect("running task missing");
        entry.state = match entry.state {
            State::Running => State::Idle,
            State::Notified => {
                self.ready.push_back(task.id);
                State::Queued
            }
            _ => unreachable!("pending task must be running"),
        };
        entry.cell = Some(task.cell);
        entry.cached_waker = Some(task.waker);
    }

    /// Retire a poll-local task before its cell and waker are destroyed.
    pub(super) fn complete(&mut self, id: TaskId) {
        let entry = self.entries.get(id.0).expect("running task missing");
        assert!(matches!(entry.state, State::Running | State::Notified));
        // The poll-local Running owns both callback-bearing values.
        assert!(entry.cell.is_none() && entry.cached_waker.is_none());
        self.entries.remove(id.0);
    }

    /// Whether at least one token remains, including stale tokens.
    pub(super) fn is_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Detach every remaining task before cleanup invokes arbitrary destructors.
    pub(super) fn clear(&mut self, retired: &mut Vec<Running>) {
        retired.reserve(self.entries.len());
        self.ready.clear();
        for index in 0..self.entries.slots_len() {
            let Some(id) = self.entries.id_at(index) else {
                continue;
            };
            let mut entry = self.entries.remove(id).unwrap();
            if let Some(cell) = entry.cell.take() {
                retired.push(Running {
                    id: TaskId(id),
                    cell,
                    waker: entry.cached_waker.take().expect("stored cell has a waker"),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Error, Runner as _, Spawner as _, Supervisor as _,
        iouring::{Config, Runner},
    };
    use commonware_utils::channel::oneshot;
    use futures::task::noop_waker;

    struct PanickingDrop;

    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            panic!("task disposal panic");
        }
    }

    #[test]
    fn cancelled_task_disposal_is_contained() {
        for catch in [false, true] {
            for placement in 0..3 {
                Runner::new(Config::default().with_catch_panics(catch)).start(
                    |context| async move {
                        let child = context.child("cancelled");
                        let child = match placement {
                            0 => child,
                            1 => child.dedicated(),
                            _ => child.shared(true),
                        };
                        let (started, ready) = oneshot::channel();
                        let handle = child.spawn(|_| async move {
                            let _guard = PanickingDrop;
                            started.send(()).unwrap();
                            std::future::pending::<()>().await;
                        });
                        ready.await.unwrap();
                        handle.abort();
                        assert!(matches!(handle.await, Err(Error::Closed)));
                        context.child("survivor").spawn(|_| async {}).await.unwrap();
                    },
                );
            }
        }
    }

    #[test]
    fn unpolled_accepted_task_disposal_is_contained() {
        for catch in [false, true] {
            Runner::new(Config::default().with_catch_panics(catch)).start(|context| async move {
                let guard = PanickingDrop;
                let _handle = context.spawn(|_| async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                });
            });
        }
    }

    fn insert(tasks: &mut Tasks) -> TaskId {
        let id = tasks.reserve();
        tasks.insert(id, Task::boxed(std::future::pending()), noop_waker());
        id
    }

    #[test]
    fn wakes_coalesce_and_survive_pending_poll() {
        let mut tasks = Tasks::default();
        let id = insert(&mut tasks);
        tasks.wake(id);
        tasks.wake(id);
        let task = tasks.take().unwrap();
        assert!(!tasks.is_ready());
        tasks.wake(id);
        tasks.wake(id);
        tasks.pending(task);
        let task = tasks.take().unwrap();
        assert!(!tasks.is_ready());
        tasks.pending(task);
        assert!(!tasks.is_ready());
        tasks.wake(id);
        assert!(tasks.take().is_some());
    }

    #[test]
    fn completion_discards_notification_and_stale_identity() {
        let mut tasks = Tasks::default();
        let id = insert(&mut tasks);
        let task = tasks.take().unwrap();
        tasks.wake(id);
        tasks.complete(id);
        drop(task);
        let next = insert(&mut tasks);
        assert_eq!(id.0.index, next.0.index);
        assert_ne!(id.0.generation, next.0.generation);
        tasks.wake(id);
        let task = tasks.take().unwrap();
        assert_eq!(task.id, next);
        tasks.pending(task);
        tasks.ready.push_back(id);
        assert!(tasks.take().is_none());
        assert!(!tasks.is_ready());
    }

    #[test]
    fn exhausted_generation_retires_slot() {
        let mut tasks = Tasks::default();
        let id = insert(&mut tasks);
        let task = tasks.take().unwrap();
        let exhausted = TaskId(tasks.entries.set_generation(id.0, u64::MAX));
        tasks.complete(exhausted);
        drop(task);
        assert_ne!(insert(&mut tasks).0.index, id.0.index);
    }

    #[test]
    fn arena_growth_preserves_poll_local_cell_and_waker() {
        let mut tasks = Tasks::default();
        let id = tasks.reserve();
        tasks.insert(id, Task::boxed(async {}), noop_waker());
        let mut running = tasks.take().unwrap();
        for _ in 0..1024 {
            insert(&mut tasks);
        }
        let mut cx = Context::from_waker(&running.waker);
        assert!(running.cell.as_mut().poll(&mut cx).is_ready());
        tasks.complete(id);
        let mut retired = Vec::new();
        tasks.clear(&mut retired);
        assert_eq!(retired.len(), 1024);
        assert!(!tasks.is_ready());
    }
}
