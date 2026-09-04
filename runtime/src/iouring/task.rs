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

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Full-width identity carried by ready tokens and routing wakers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TaskId {
    /// Index in the owning worker's arena.
    index: usize,
    /// Generation of this occupation of the slot.
    generation: u64,
}

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
    /// No task occupies this slot.
    Complete,
}

/// One generational slot. A running cell and waker live on the worker's stack.
struct Entry {
    /// Current slot identity, never wrapped.
    generation: u64,
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
    entries: Vec<Entry>,
    /// Vacant slots whose generations still have room to advance.
    free: Vec<usize>,
    /// FIFO notifications, including harmless stale tokens.
    ready: VecDeque<TaskId>,
}

impl Tasks {
    /// Reserve a slot and queue space before constructing its routing waker.
    ///
    /// The caller constructs the waker outside Local, then calls `insert`
    /// without permitting another insertion between these operations.
    pub(super) fn reserve(&mut self) -> TaskId {
        self.ready.reserve(1);
        if let Some(&index) = self.free.last() {
            TaskId {
                index,
                generation: self.entries[index].generation,
            }
        } else {
            self.entries.reserve(1);
            TaskId {
                index: self.entries.len(),
                generation: 0,
            }
        }
    }

    /// Insert previously reserved ownership without invoking any callback.
    pub(super) fn insert(&mut self, id: TaskId, cell: Pin<Box<dyn Runnable>>, waker: Waker) {
        let entry = Entry {
            generation: id.generation,
            state: State::Queued,
            cell: Some(cell),
            cached_waker: Some(waker),
        };
        if id.index == self.entries.len() {
            self.entries.push(entry);
        } else {
            assert_eq!(self.free.pop(), Some(id.index));
            assert_eq!(self.entries[id.index].generation, id.generation);
            assert_eq!(self.entries[id.index].state, State::Complete);
            self.entries[id.index] = entry;
        }
        self.ready.push_back(id);
    }

    /// Record a notification, coalescing queued and poll-local duplicates.
    pub(super) fn wake(&mut self, id: TaskId) {
        // Reserve before changing state so allocation failure cannot leave an
        // entry marked Queued without its corresponding ready token.
        self.ready.reserve(1);
        let Some(entry) = self.entries.get_mut(id.index) else {
            return;
        };
        if entry.generation != id.generation {
            return;
        }
        match entry.state {
            State::Idle => {
                entry.state = State::Queued;
                self.ready.push_back(id);
            }
            State::Running => entry.state = State::Notified,
            State::Queued | State::Notified | State::Complete => {}
        }
    }

    /// Consume one token, counting stale tokens toward the caller's budget.
    ///
    /// `None` means this token was stale or the lane was empty. The caller uses
    /// `is_ready` to distinguish an exhausted lane from remaining stale tokens.
    pub(super) fn take(&mut self) -> Option<Running> {
        let id = self.ready.pop_front()?;
        let entry = self.entries.get_mut(id.index)?;
        if entry.generation != id.generation || entry.state != State::Queued {
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
        self.ready.reserve(1);
        let entry = &mut self.entries[task.id.index];
        assert_eq!(entry.generation, task.id.generation);
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
        self.free.reserve(1);
        let entry = &mut self.entries[id.index];
        assert_eq!(entry.generation, id.generation);
        assert!(matches!(entry.state, State::Running | State::Notified));
        entry.state = State::Complete;
        if let Some(next) = entry.generation.checked_add(1) {
            entry.generation = next;
            self.free.push(id.index);
        }
    }

    /// Whether at least one token remains, including stale tokens.
    pub(super) fn is_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Detach every remaining task before cleanup invokes arbitrary destructors.
    pub(super) fn clear(&mut self, retired: &mut Vec<Running>) {
        retired.reserve(self.entries.len());
        self.ready.clear();
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if let Some(cell) = entry.cell.take() {
                retired.push(Running {
                    id: TaskId {
                        index,
                        generation: entry.generation,
                    },
                    cell,
                    waker: entry.cached_waker.take().expect("stored cell has a waker"),
                });
            }
            entry.state = State::Complete;
        }
        self.free.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker;

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
        assert_eq!(id.index, next.index);
        assert_ne!(id.generation, next.generation);
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
        tasks.entries[id.index].generation = u64::MAX;
        tasks.complete(TaskId {
            generation: u64::MAX,
            ..id
        });
        drop(task);
        assert_ne!(insert(&mut tasks).index, id.index);
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
