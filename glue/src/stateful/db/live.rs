//! Access to the live database. A [`Writer`] owns it, only the writer can
//! mutate it, and the writer hands out cloneable [`Reader`]s that can only
//! read it.
//!
//! Both sides go through a [`TracedAsyncRwLock`], which is fair and
//! write-preferring. A waiting mutation blocks later reads and cannot be
//! starved, while reads already granted finish first.
//!
//! A mutation that is interrupted poisons the writer and destroys the
//! [`Writer`] value with it, so a subsequent mutation can't happen.
//! That only happens when the owning task is torn down or the mutation
//! panics, both fatal. Dropping the writer closes reads, so readers cannot
//! silently go on serving a database that can never advance.
//!
//! A [`Reader`] read of a dropped or poisoned writer returns [`Closed`],
//! which only happens while the writer's owner is going down. Callers must
//! treat it as an instruction to stop, never as a data-level failure. The
//! writer itself reads infallibly, because a live writer proves a live
//! database.
//!
//! The lock is not reentrant. Never hold a read guard while acquiring another
//! on the same writer, or a mutation queued between the two will deadlock
//! both.

use commonware_utils::sync::{AsyncRwLockReadGuard, TracedAsyncRwLock};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use thiserror::Error;

/// The writer was dropped, or poisoned by an interrupted mutation. The
/// database is gone and the caller must stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("database writer dropped or poisoned")]
pub struct Closed;

enum State<T> {
    Live(T),
    /// A mutation was interrupted before restoring the database. Fatal.
    Poisoned,
}

/// Shared between a [`Writer`] and its [`Reader`]s. `state` records whether
/// the database is present; `closed` records that the writer is gone.
struct Inner<T> {
    state: TracedAsyncRwLock<State<T>>,
    /// Set when the [`Writer`] is dropped; an interrupted mutation drops it
    /// too.
    closed: AtomicBool,
}

/// Owns the live database and hands out [`Reader`]s.
/// [`mutate`](Self::mutate) is the only way to mutate it.
pub struct Writer<T>(Arc<Inner<T>>);

impl<T> Writer<T> {
    /// Wrap `db` in a new writer.
    pub fn new(db: T) -> Self {
        Self(Arc::new(Inner {
            state: TracedAsyncRwLock::new("stateful.db.live", State::Live(db)),
            closed: AtomicBool::new(false),
        }))
    }

    /// Acquire a read guard.
    pub async fn read(&self) -> AsyncRwLockReadGuard<'_, T> {
        AsyncRwLockReadGuard::map(self.0.state.read().await, |state| match state {
            State::Live(db) => db,
            // Poisoning destroys the writer, so a live writer cannot observe it.
            State::Poisoned => unreachable!("a writer only exists while its state is live"),
        })
    }

    /// Create a [`Reader`] of the writer's database.
    pub fn reader(&self) -> Reader<T> {
        Reader(self.0.clone())
    }

    /// Run a mutation on the database, returning the writer on completion.
    /// Dropping the future or panicking poisons the writer and destroys it.
    pub async fn mutate<F, Fut, R>(self, mutation: F) -> (Self, R)
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = (T, R)>,
    {
        let mut guard = self.0.state.write().await;
        let State::Live(db) = std::mem::replace(&mut *guard, State::Poisoned) else {
            unreachable!("a writer only exists while its state is live");
        };
        let (db, result) = mutation(db).await;
        *guard = State::Live(db);
        drop(guard);
        (self, result)
    }
}

impl<T> Drop for Writer<T> {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
    }
}

/// Cloneable reader of a [`Writer`]'s database.
pub struct Reader<T>(Arc<Inner<T>>);

impl<T> Reader<T> {
    /// Acquire a read guard, or report the writer dropped or poisoned.
    pub async fn read(&self) -> Result<AsyncRwLockReadGuard<'_, T>, Closed> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(Closed);
        }
        let guard = self.0.state.read().await;
        AsyncRwLockReadGuard::try_map(guard, |state| match state {
            State::Live(db) => Some(db),
            State::Poisoned => None,
        })
        .map_err(|_| Closed)
    }
}

impl<T> Clone for Reader<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
    use commonware_utils::channel::oneshot;
    use futures::{FutureExt as _, future};
    use std::time::Duration;

    /// Mutations run back to back, and the writer and its readers see each
    /// result.
    #[test]
    fn mutations_chain() {
        deterministic::Runner::default().start(|_context| async move {
            let writer = Writer::new(0u64);
            let reader = writer.reader();

            let (writer, ()) = writer.mutate(|db| async move { (db + 1, ()) }).await;
            let (writer, seen) = writer.mutate(|db| async move { (db + 1, db) }).await;
            assert_eq!(seen, 1, "the second mutation starts from the first");
            assert_eq!(*writer.read().await, 2);
            assert_eq!(*reader.read().await.expect("writer is live"), 2);
        });
    }

    /// A steady stream of reads cannot starve a waiting mutation.
    #[test]
    fn mutation_is_not_starved_by_read_storm() {
        deterministic::Runner::default().start(|context| async move {
            let writer = Writer::new(0u64);

            let mut readers = Vec::new();
            for worker in ["r0", "r1", "r2", "r3"] {
                let reader = writer.reader();
                readers.push(context.child(worker).spawn(move |ctx| async move {
                    loop {
                        if *reader.read().await.expect("writer is live") == 1 {
                            return;
                        }
                        ctx.sleep(Duration::from_millis(1)).await;
                    }
                }));
            }

            context.sleep(Duration::from_millis(5)).await;
            let (_writer, ()) = writer
                .mutate(|db| async move {
                    assert_eq!(db, 0);
                    (db + 1, ())
                })
                .await;

            for reader in readers {
                reader.await.expect("reader should observe the mutation");
            }
        });
    }

    /// A read waits for a running mutation and then sees its result, never
    /// a gap.
    #[test]
    fn reads_wait_out_a_running_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let writer = Writer::new(0u64);
            let reader = writer.reader();
            let (release_tx, release) = oneshot::channel::<()>();
            let (acquired_tx, acquired) = oneshot::channel::<()>();

            let mutator = context.child("writer").spawn(move |_| async move {
                let (_writer, ()) = writer
                    .mutate(|db| async move {
                        let _ = acquired_tx.send(());
                        let _ = release.await;
                        (db + 1, ())
                    })
                    .await;
            });

            acquired.await.expect("mutation must start");
            let read = reader.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a read must wait while a mutation holds the write lock",
            );

            release_tx.send(()).expect("mutation is waiting");
            mutator.await.expect("mutation completes");
            assert_eq!(
                *read.await.expect("writer is live"),
                1,
                "the read sees the mutated state",
            );
        });
    }

    /// Dropping the writer closes reads. A later read reports [`Closed`]
    /// instead of serving a database that can never advance.
    #[test]
    fn dropped_writer_closes_reads() {
        deterministic::Runner::default().start(|_context| async move {
            let writer = Writer::new(0u64);
            let reader = writer.reader();
            drop(writer);
            assert_eq!(reader.read().await.err(), Some(Closed));
        });
    }

    /// Dropping a mutation partway through poisons the writer and destroys
    /// it, so no second mutation can exist. A later read reports [`Closed`]
    /// instead of seeing missing state.
    #[test]
    fn interrupted_mutation_poisons() {
        deterministic::Runner::default().start(|_context| async move {
            let writer = Writer::new(0u64);
            let reader = writer.reader();
            let (started_tx, started) = oneshot::channel::<()>();

            let mut mutation = Box::pin(writer.mutate(|db| async move {
                let _ = started_tx.send(());
                future::pending::<()>().await;
                (db, ())
            }));
            assert!(
                mutation.as_mut().now_or_never().is_none(),
                "mutation must still be running",
            );
            started.await.expect("mutation must reach its closure");
            drop(mutation);

            assert_eq!(reader.read().await.err(), Some(Closed));
        });
    }
}
