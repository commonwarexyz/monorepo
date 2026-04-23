//! Dedicated single-thread executor used by Tokio `dedicated()` and
//! `colocated()` spawns.
//!
//! The public runtime API keeps [`crate::Spawner`] and [`crate::Metrics`]
//! contexts `Send + Sync`, which means a context carrying dedicated affinity may
//! be moved to another thread before it spawns a colocated child. Tokio's
//! [`tokio::task::LocalSet`] is not a sendable handle for that use case, so this
//! module provides a small dedicated executor abstraction instead:
//!
//! - each dedicated branch owns one OS thread;
//! - that thread enters the shared Tokio runtime once and polls all branch
//!   tasks there;
//! - callers only hold a sendable [`DedicatedExecutor`] handle that can submit
//!   more work onto the owner thread.
//!
//! `async-task` supplies the typed task allocation and wakeup machinery, while
//! this module supplies the dedicated thread, queueing, lifecycle tracking, and
//! "root task exit closes the branch" semantics required by `colocated()`.

use crate::utils;
use async_task::Runnable;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
};

/// Work submitted to a dedicated executor thread.
enum DedicatedWork {
    /// Poll this task on the dedicated thread.
    Runnable(Runnable),
    /// Wake the executor loop so it can observe a state change, such as the
    /// branch closing after its root exits.
    Wake,
}

/// Shared state for a dedicated executor thread.
struct DedicatedInner {
    /// Queue used by remote submitters and task wakeups to hand runnable tasks
    /// back to the owner thread.
    tx: mpsc::Sender<DedicatedWork>,
    /// Whether the branch still accepts new colocated descendants.
    running: AtomicBool,
    /// Number of tasks that still need to finish before the thread may exit.
    active: AtomicUsize,
}

impl DedicatedInner {
    /// Mark the dedicated executor as closed and wake its thread so it can
    /// observe the state transition.
    fn close(&self) {
        if self.running.swap(false, Ordering::AcqRel) {
            let _ = self.tx.send(DedicatedWork::Wake);
        }
    }
}

/// A sendable handle for submitting work onto a dedicated executor thread.
#[derive(Clone)]
pub(crate) struct DedicatedExecutor {
    inner: Arc<DedicatedInner>,
}

/// Decrements the active task count when a task leaves the dedicated executor.
struct ActiveGuard {
    inner: Arc<DedicatedInner>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1
            && !self.inner.running.load(Ordering::Acquire)
        {
            let _ = self.inner.tx.send(DedicatedWork::Wake);
        }
    }
}

/// Closes the dedicated executor once its root task exits.
struct RootGuard {
    inner: Arc<DedicatedInner>,
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl DedicatedExecutor {
    /// Spawn a new dedicated executor thread that keeps Tokio's shared runtime
    /// entered for the lifetime of the executor loop.
    pub(crate) fn start(handle: tokio::runtime::Handle, stack_size: usize) -> Arc<Self> {
        // The sender lives in the shared handle so callers can submit from any
        // thread. The receiver is owned by the dedicated thread and is the only
        // place tasks are ever polled.
        let (tx, rx) = mpsc::channel();
        let executor = Arc::new(Self {
            inner: Arc::new(DedicatedInner {
                tx,
                running: AtomicBool::new(true),
                active: AtomicUsize::new(0),
            }),
        });
        let inner = executor.inner.clone();

        utils::thread::spawn(stack_size, move || {
            // Dedicated tasks still use Tokio-backed time, DNS, networking,
            // storage, and blocking facilities. Enter the shared runtime once
            // and then poll our own single-threaded task queue on top of it.
            let _entered = handle.enter();
            loop {
                // Once the branch is closed and all outstanding tasks have
                // drained, the dedicated thread can exit.
                if !inner.running.load(Ordering::Acquire)
                    && inner.active.load(Ordering::Acquire) == 0
                {
                    break;
                }

                match rx.recv() {
                    Ok(DedicatedWork::Runnable(runnable)) => {
                        // `Runnable::run()` returns whether the task was woken
                        // while it was running. The scheduling policy here does
                        // not need that information, so we ignore it.
                        let _ = runnable.run();
                    }
                    Ok(DedicatedWork::Wake) => {
                        // This is just a nudge to re-check `running` and
                        // `active`; there is no runnable payload to process.
                    }
                    Err(_) => break,
                }
            }
        });

        executor
    }

    /// Returns whether this dedicated executor still accepts new colocated
    /// children.
    pub(crate) fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Acquire)
    }

    /// Spawn the root task for a dedicated branch. When it exits, the branch
    /// stops accepting new colocated descendants.
    pub(crate) fn spawn_root<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let inner = self.inner.clone();
        self.spawn_task(async move {
            let _guard = RootGuard { inner };
            future.await;
        });
    }

    /// Spawn a colocated descendant onto the dedicated thread.
    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Stale clones must fail at spawn time once the dedicated root has
        // exited; silently dropping work or reviving the branch would violate
        // the `colocated()` contract.
        assert!(
            self.is_running(),
            "`colocated()` requires a running dedicated ancestor"
        );
        self.spawn_task(future);
    }

    /// Schedule a task on the dedicated executor using `async-task` so the
    /// concrete future type stays inside the task allocation rather than being
    /// erased behind `Box<dyn Future>`.
    fn spawn_task<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Count the task before it is scheduled so the branch cannot shut down
        // between submission and the first poll.
        self.inner.active.fetch_add(1, Ordering::AcqRel);

        let task_inner = self.inner.clone();
        let schedule_inner = self.inner.clone();
        let schedule = move |runnable: Runnable| {
            // Both the initial submission and all later wakeups return here,
            // which keeps the dedicated thread as the only poller.
            let _ = schedule_inner.tx.send(DedicatedWork::Runnable(runnable));
        };

        let wrapped = async move {
            // The guard releases the active task count when the future
            // completes, is aborted, or unwinds through the task harness.
            let _guard = ActiveGuard { inner: task_inner };
            future.await;
        };

        // `async-task` stores the concrete future inside its own task
        // allocation, so the queue only needs to carry uniform `Runnable`
        // handles instead of boxed trait objects.
        let (runnable, task) = async_task::spawn(wrapped, schedule);
        // Our public `Handle<T>` already owns task completion, abort, panic,
        // and supervision semantics, so we detach the `async-task` handle and
        // keep only the runnable side.
        task.detach();
        runnable.schedule();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        thread,
        time::Duration,
    };

    /// Wait until the executor closes its branch or time out if something is
    /// keeping the root task alive unexpectedly.
    fn wait_for_close(executor: &DedicatedExecutor) {
        for _ in 0..200 {
            if !executor.is_running() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("dedicated executor did not close in time");
    }

    #[test]
    fn test_remote_submit_runs_on_dedicated_owner_thread() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let executor = DedicatedExecutor::start(
            runtime.handle().clone(),
            utils::thread::system_thread_stack_size(),
        );

        let (owner_tx, owner_rx) = mpsc::channel();
        let (child_tx, child_rx) = mpsc::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        // Keep the root task alive so we can submit a colocated child from the
        // test thread while the branch is still running.
        executor.spawn_root(async move {
            owner_tx.send(thread::current().id()).unwrap();
            let _ = release_rx.await;
        });

        let owner_thread = owner_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        executor.spawn(async move {
            child_tx.send(thread::current().id()).unwrap();
        });
        let child_thread = child_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert_eq!(owner_thread, child_thread);

        assert!(release_tx.send(()).is_ok());
        wait_for_close(&executor);
    }

    #[test]
    fn test_spawn_rejects_after_root_exit() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let executor = DedicatedExecutor::start(
            runtime.handle().clone(),
            utils::thread::system_thread_stack_size(),
        );

        let (done_tx, done_rx) = mpsc::channel();
        executor.spawn_root(async move {
            done_tx.send(()).unwrap();
        });

        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        wait_for_close(&executor);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            executor.spawn(async move {});
        }));
        assert!(panic.is_err());
    }
}
