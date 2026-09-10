//! Worker-local tasks and FIFO scheduling.
//!
//! The worker takes the task and its cached waker out of [`Tasks`] before polling,
//! so user code can spawn more tasks without holding a borrow or a reference into
//! the slab. Task destruction also runs outside worker borrows.
//!
//! A queued task has one FIFO entry. Wakes during polling record a notification,
//! which requeues the task if it returns pending. Completion retires the slot
//! even if a wake arrived during the poll.
//!
//! Foreign spawns and wakes go through the worker's mailbox. Generational IDs
//! keep delayed wakes from scheduling a new task in a reused slot.

use super::{
    mailbox::{Mailbox, Message},
    runtime,
    slab::{Id, Slab},
};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll, Wake, Waker},
};

/// Root or spawned task selected by a routing waker.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// The root future pinned separately on the worker's stack.
    Root,
    /// A generational entry in the worker's task slab.
    Task(TaskId),
}

/// Route a wake without retaining the task or its worker.
pub struct TaskWaker {
    /// Weak origin identity, retained even after the worker has shut down.
    mailbox: Weak<Mailbox>,
    /// Root-ready flag or task identity to notify on the owning worker.
    target: Target,
}

impl TaskWaker {
    /// Allocate a waker that notifies the target on its owning worker.
    pub fn new(mailbox: Weak<Mailbox>, target: Target) -> Arc<Self> {
        Arc::new(Self { mailbox, target })
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(local) = runtime::owner(&self.mailbox) {
            let mut local = local.borrow_mut();

            // Local wakes update readiness without a mailbox round trip.
            if !local.closing {
                match self.target {
                    Target::Root => local.root_ready = true,
                    Target::Task(id) => local.tasks.wake(id),
                }
            }
            return;
        }

        // A foreign waker carries only the target's identity. The owning worker
        // checks the generation when it applies the message.
        if let Some(mailbox) = self.mailbox.upgrade() {
            let _ = mailbox.send(Message::Wake(self.target));
        }
    }
}

/// Generational identity carried by the ready queue and routing wakers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskId(Id);

/// Pinned future owned by the scheduler until completion or cancellation.
pub type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Pinned task with a separate poll entry point for its execution wrapper.
pub struct Task<F> {
    /// Future pinned in place with the enclosing task until destruction.
    future: F,
}

impl<F: Future<Output = ()> + Send + 'static> Task<F> {
    /// Allocate the task and erase its concrete type for scheduling.
    pub fn boxed(future: F) -> BoxedTask {
        Box::pin(Self { future })
    }
}

impl<F: Future<Output = ()> + Send + 'static> Future for Task<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: The pinned Task allocation owns `future`. Neither this type
        // nor its scheduler moves the field after pinning, and destruction runs
        // in place. This projection grants exclusive access only for this poll.
        unsafe { self.map_unchecked_mut(|task| &mut task.future) }.poll(cx)
    }
}

/// Scheduling state changed exclusively by the owning worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Pending without a notification or ready token.
    Idle,
    /// Exactly one entry exists in the ready queue.
    Queued,
    /// The worker has taken the task for polling.
    Running,
    /// A wake occurred during the current poll.
    Notified,
}

/// Task state retained in the slab, including while the worker polls the future.
struct Entry {
    /// Scheduling state, changed only by the owning worker.
    state: State,
    /// Task allocation when it is not being polled.
    task: Option<BoxedTask>,
    /// Routing waker moved out alongside the task for each poll.
    waker: Option<Waker>,
}

/// Task and waker held outside the slab for polling or destruction.
pub struct Running {
    /// Identity used to restore or retire the entry after polling.
    pub id: TaskId,
    /// Pinned task allocation.
    pub task: BoxedTask,
    /// Cached waker borrowed during polling without cloning.
    pub waker: Waker,
}

/// Worker-owned tasks and their ready queue.
#[derive(Default)]
pub struct Tasks {
    /// Generational slots owned by this worker.
    entries: Slab<Entry>,
    /// Exactly one FIFO entry for every queued task.
    ready: VecDeque<TaskId>,
}

impl Tasks {
    /// Whether the origin worker currently accepts tasks.
    ///
    /// This does not reserve a place. Registration checks again after construction.
    pub fn is_open(mailbox: &Weak<Mailbox>) -> bool {
        if let Some(local) = runtime::owner(mailbox) {
            // The owning thread can check closure without locking the mailbox.
            return !local.borrow().closing;
        }

        // Foreign callers use the mailbox's acceptance state.
        mailbox.upgrade().is_some_and(|mailbox| mailbox.is_open())
    }

    /// Register on the origin worker, directly or through its mailbox.
    ///
    /// Returns rejected tasks for destruction outside worker borrows.
    pub fn register(mailbox: &Weak<Mailbox>, task: BoxedTask) -> Result<(), BoxedTask> {
        // The factory runs after is_open, so check acceptance again before
        // taking ownership of the constructed task.
        if let Some(local) = runtime::owner(mailbox) {
            let mut local = local.borrow_mut();
            if local.closing {
                return Err(task);
            }

            local.tasks.insert(task, mailbox.clone());
            return Ok(());
        }

        // Foreign callers transfer ownership through the mailbox. If closure
        // wins the race, return the task for destruction by the caller.
        let Some(mailbox) = mailbox.upgrade() else {
            return Err(task);
        };
        match mailbox.send(Message::Spawn(task)) {
            Ok(()) => Ok(()),
            Err(Message::Spawn(task)) => Err(task),
            Err(_) => unreachable!("spawn publication returned another message kind"),
        }
    }

    /// Insert a task and its routing waker without invoking user callbacks.
    pub fn insert(&mut self, task: BoxedTask, mailbox: Weak<Mailbox>) -> TaskId {
        // Routing wakers contain only our mailbox and task identity. Creating
        // one under the worker borrow cannot invoke user callbacks.
        let id = TaskId(self.entries.insert_with(|id| Entry {
            state: State::Queued,
            task: Some(task),
            waker: Some(TaskWaker::new(mailbox, Target::Task(TaskId(id))).into()),
        }));
        self.ready.push_back(id);
        id
    }

    /// Record a wake, coalescing duplicates and ignoring stale task IDs.
    pub fn wake(&mut self, id: TaskId) {
        let Some(entry) = self.entries.get_mut(id.0) else {
            return;
        };

        match entry.state {
            State::Idle => {
                entry.state = State::Queued;
                self.ready.push_back(id);
            }
            // The polling worker owns the task until pending or complete runs.
            State::Running => entry.state = State::Notified,
            State::Queued | State::Notified => {}
        }
    }

    /// Take the oldest ready task and its waker for polling outside the borrow.
    pub fn take(&mut self) -> Option<Running> {
        let id = self.ready.pop_front()?;
        let entry = self.entries.get_mut(id.0).expect("queued task missing");
        assert_eq!(entry.state, State::Queued, "ready task must be queued");

        // Leave the state behind so a wake during polling can be remembered.
        entry.state = State::Running;
        Some(Running {
            id,
            task: entry.task.take().expect("queued task has a future"),
            waker: entry.waker.take().expect("queued task has a waker"),
        })
    }

    /// Restore a pending task, requeueing it if a wake arrived during polling.
    pub fn pending(&mut self, running: Running) {
        let entry = self
            .entries
            .get_mut(running.id.0)
            .expect("running task missing");

        entry.state = match entry.state {
            State::Running => State::Idle,
            State::Notified => {
                // Join the tail so self-waking tasks cannot skip other ready work.
                self.ready.push_back(running.id);
                State::Queued
            }
            _ => unreachable!("pending task must be running"),
        };

        entry.task = Some(running.task);
        entry.waker = Some(running.waker);
    }

    /// Retire a running task before the worker destroys its future and waker.
    pub fn complete(&mut self, id: TaskId) {
        let entry = self.entries.get(id.0).expect("running task missing");
        assert!(matches!(entry.state, State::Running | State::Notified));

        // Running owns both values, so removing the entry invokes no user code.
        // A notification during the final poll needs no ready-queue entry.
        assert!(entry.task.is_none() && entry.waker.is_none());
        self.entries.remove(id.0);
    }

    /// Whether at least one queued task remains.
    pub fn is_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Detach every remaining task before cleanup invokes arbitrary destructors.
    pub fn clear(&mut self, retired: &mut Vec<Running>) {
        // Reserve before detaching tasks so pushing them cannot allocate.
        retired.reserve(self.entries.len());
        self.ready.clear();

        // Idle tasks have no ready token, so cleanup must walk the slab.
        for index in 0..self.entries.slots() {
            let Some(id) = self.entries.id_at(index) else {
                continue;
            };

            // Retiring the registration makes any delayed wake stale.
            let Entry { task, waker, .. } = self.entries.remove(id).unwrap();

            // Tasks taken for polling remain with the worker. Stored tasks and
            // their wakers are returned for destruction after the borrow ends.
            if let Some(task) = task {
                retired.push(Running {
                    id: TaskId(id),
                    task,
                    waker: waker.expect("stored task has a waker"),
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
        utils::Execution,
    };
    use commonware_utils::channel::oneshot;
    use std::{
        future::pending,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    /// Count destruction before injecting a task-disposal panic.
    struct PanickingDrop(Arc<AtomicUsize>);

    impl Drop for PanickingDrop {
        fn drop(&mut self) {
            // Count only after checking the borrow. Otherwise contain could
            // swallow a borrow panic and make the disposal test pass anyway.
            if let Some(local) = runtime::current() {
                let _borrow = local.borrow_mut();
            }
            self.0.fetch_add(1, Ordering::Relaxed);
            panic!("task disposal panic");
        }
    }

    /// Record when a task's captured state is destroyed.
    struct DropCount(Arc<AtomicUsize>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Insert a pending task without a live worker or mailbox.
    fn insert(tasks: &mut Tasks) -> TaskId {
        tasks.insert(Task::boxed(pending()), Weak::new())
    }

    #[test]
    fn test_cancelled_task_disposal_is_contained() {
        for catch in [false, true] {
            for execution in [
                Execution::default(),
                Execution::Dedicated,
                Execution::Shared(true),
            ] {
                let drops = Arc::new(AtomicUsize::new(0));
                let task_drops = drops.clone();

                Runner::new(Config::default().with_catch_panics(catch)).start(
                    |context| async move {
                        let child = context.child("cancelled");
                        let child = match execution {
                            Execution::Dedicated => child.dedicated(),
                            Execution::Shared(blocking) => child.shared(blocking),
                        };
                        let (started, ready) = oneshot::channel();
                        let handle = child.spawn(|context| async move {
                            let _guard = PanickingDrop(task_drops);
                            assert!(started.send(context.child("retained")).is_ok());
                            pending::<()>().await;
                        });

                        // Abort after the task has installed its guard. The panic
                        // comes from cancellation, regardless of user-poll policy.
                        let retained = ready.await.unwrap();
                        handle.abort();
                        assert!(matches!(handle.await, Err(Error::Closed)));

                        // Disposal must close the supervision subtree before the
                        // parent handle resolves, even when destruction panics.
                        let invoked = Arc::new(AtomicBool::new(false));
                        let factory_invoked = invoked.clone();
                        let result = retained
                            .spawn(move |_| {
                                factory_invoked.store(true, Ordering::Relaxed);
                                async {}
                            })
                            .await;
                        assert!(
                            !invoked.load(Ordering::Relaxed),
                            "cancelled descendant invoked its spawn factory"
                        );
                        assert!(matches!(result, Err(Error::Closed)));

                        context.child("survivor").spawn(|_| async {}).await.unwrap();
                    },
                );

                assert_eq!(drops.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[test]
    fn test_unpolled_task_disposal_is_contained() {
        for catch in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let guard = PanickingDrop(drops.clone());
            let polled = Arc::new(AtomicBool::new(false));
            let task_polled = polled.clone();

            Runner::new(Config::default().with_catch_panics(catch)).start(|context| async move {
                // The root returns without yielding, leaving the guard captured
                // in an accepted task that shutdown must destroy without polling.
                context.child("unpolled").spawn(|_| async move {
                    let _guard = guard;
                    task_polled.store(true, Ordering::Relaxed);
                    pending::<()>().await;
                });
            });

            assert!(!polled.load(Ordering::Relaxed));
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn test_wakes_coalesce_and_preserve_fifo_order() {
        let mut tasks = Tasks::default();
        assert!(!tasks.is_ready());
        assert!(tasks.take().is_none());

        let first = insert(&mut tasks);
        let second = insert(&mut tasks);

        // Duplicate wakes must neither duplicate a queued task nor change its place.
        tasks.wake(first);
        tasks.wake(first);
        let task = tasks.take().unwrap();
        assert_eq!(task.id, first);

        // A self-wake during polling joins the tail after already queued work,
        // including tasks inserted while the first task was being polled.
        tasks.wake(first);
        tasks.wake(first);
        let third = insert(&mut tasks);
        tasks.pending(task);

        for id in [second, third, first] {
            let task = tasks.take().unwrap();
            assert_eq!(task.id, id);
            tasks.pending(task);
        }
        assert!(!tasks.is_ready());

        // An idle task rejoins the FIFO on its first wake, and further wakes coalesce.
        tasks.wake(third);
        tasks.wake(third);
        tasks.wake(second);
        for id in [third, second] {
            let task = tasks.take().unwrap();
            assert_eq!(task.id, id);
            tasks.complete(id);
            drop(task);
        }
        assert!(tasks.take().is_none());
    }

    #[test]
    fn test_completion_rejects_stale_wakes() {
        for notified in [false, true] {
            let mut tasks = Tasks::default();
            let id = insert(&mut tasks);
            let task = tasks.take().unwrap();
            if notified {
                tasks.wake(id);
            }

            // A final-poll notification must not leave a ready entry behind.
            tasks.complete(id);
            drop(task);
            tasks.wake(id);
            assert!(!tasks.is_ready());

            let next = insert(&mut tasks);
            assert_eq!(id.0.index, next.0.index);
            let task = tasks.take().unwrap();
            assert_eq!(task.id, next);
            tasks.pending(task);

            // Keep the replacement idle, so a stale wake cannot be hidden by
            // coalescing with an existing ready entry.
            tasks.wake(id);
            assert!(tasks.take().is_none());
        }
    }

    #[test]
    fn test_clear_detaches_tasks_in_each_state() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut tasks = Tasks::default();
        let ids = [(); 4].map(|_| {
            let guard = DropCount(drops.clone());
            tasks.insert(
                Task::boxed(async move {
                    let _guard = guard;
                    pending::<()>().await;
                }),
                Weak::new(),
            )
        });

        // Leave one task idle, two taken for polling, and one still queued.
        let task = tasks.take().unwrap();
        tasks.pending(task);
        let running = tasks.take().unwrap();
        let notified = tasks.take().unwrap();
        tasks.wake(notified.id);

        // Clear appends the two stored tasks without dropping them or disturbing
        // either task whose ownership has already left the slab.
        let mut retired = vec![notified];
        tasks.clear(&mut retired);
        tasks.clear(&mut retired);
        assert_eq!(retired.len(), 3);
        assert_eq!(tasks.entries.len(), 0);
        assert!(!tasks.is_ready());
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        for id in ids {
            tasks.wake(id);
        }
        assert!(tasks.take().is_none());

        drop(retired);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        drop(running);
        assert_eq!(drops.load(Ordering::Relaxed), 4);
    }
}
