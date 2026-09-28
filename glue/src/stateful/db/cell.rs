//! Splits access to a live database. A unique [`Writer`] runs consuming
//! mutations, and cloneable [`Reader`]s hand out short read guards, one per
//! storage call.
//!
//! The cell is a fair, write-preferring read-write lock: a waiting mutation
//! blocks new read guards but cannot be starved, and guards already granted
//! finish first. A guard proves the database is present for one call, not
//! that the caller's batch is still current (see
//! [`commonware_storage::qmdb::Error::StaleRead`]).
//!
//! Never hold two read guards at once, even on different cells. The lock is
//! not reentrant, and because a waiting mutation blocks new guards, two tasks
//! each holding one cell's guard while waiting on the other's deadlock once
//! both cells have a mutation waiting.

use commonware_utils::sync::{AsyncRwLockReadGuard, TracedAsyncRwLock};
use futures::future;
use std::{
    future::Future,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

enum State<T> {
    Live(T),
    /// A mutation was interrupted before restoring the database. Fatal.
    Poisoned,
    /// The writer dropped and reclaimed the database.
    Closed,
}

struct Cell<T> {
    /// Identifies this cell in lock traces and parking logs.
    label: &'static str,
    state: TracedAsyncRwLock<State<T>>,
    /// Set when the writer drops. One-way, so a relaxed load suffices.
    closed: AtomicBool,
}

impl<T> Cell<T> {
    async fn read(&self) -> ReadGuard<'_, T> {
        let guard = self.state.read().await;
        if self.closed.load(Ordering::Relaxed) {
            // The writer is gone. Park rather than serve frozen state.
            drop(guard);
            tracing::debug!(cell = self.label, "database cell closed, parking reader");
            return future::pending().await;
        }
        match AsyncRwLockReadGuard::try_map(guard, |state| match state {
            State::Live(db) => Some(db),
            State::Poisoned | State::Closed => None,
        }) {
            Ok(guard) => ReadGuard(guard),
            Err(guard) => {
                // Poisoning only happens during actor teardown. Park until
                // this task is dropped with it.
                drop(guard);
                tracing::debug!(cell = self.label, "database cell poisoned, parking reader");
                future::pending().await
            }
        }
    }
}

/// Split `db` into its unique [`Writer`] and a cloneable [`Reader`].
pub fn split<T>(db: T) -> (Writer<T>, Reader<T>) {
    let writer = Writer::new("database_cell", db);
    let reader = writer.reader();
    (writer, reader)
}

/// The unique handle that mutates the database behind a cell.
///
/// Not [`Clone`], so at most one exists. Dropping it closes the cell, and
/// later reads park rather than serve frozen state. The drop also drops the
/// database unless a read guard is held at that moment, in which case the
/// remaining [`Reader`]s keep it alive.
pub struct Writer<T>(Arc<Cell<T>>);

impl<T> Drop for Writer<T> {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Relaxed);
        if let Some(mut guard) = self.0.state.try_write() {
            *guard = State::Closed;
        }
    }
}

impl<T> Writer<T> {
    /// Put `db` in a fresh cell identified by `label` in lock traces, and
    /// return its writer.
    pub fn new(label: &'static str, db: T) -> Self {
        Self(Arc::new(Cell {
            label,
            state: TracedAsyncRwLock::new(label, State::Live(db)),
            closed: AtomicBool::new(false),
        }))
    }

    /// A reader over the writer's cell.
    pub fn reader(&self) -> Reader<T> {
        Reader(self.0.clone())
    }

    /// Run one consuming mutation to completion, returning the writer.
    ///
    /// Starts once every granted read guard drops, each covering at most one
    /// storage call, since new read guards queue behind it. Dropping the future
    /// mid-flight poisons the cell, and later reads park.
    pub async fn mutate<F, Fut, R>(self, mutation: F) -> (Self, R)
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = (T, R)>,
    {
        let mut guard = self.0.state.write().await;
        let State::Live(db) = std::mem::replace(&mut *guard, State::Poisoned) else {
            unreachable!("a writer only exists while its cell is live")
        };
        let (db, result) = mutation(db).await;
        *guard = State::Live(db);
        drop(guard);
        (self, result)
    }
}

/// A cloneable read handle over the database behind a cell.
pub struct Reader<T>(Arc<Cell<T>>);

impl<T> Clone for Reader<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Reader<T> {
    /// Acquire a read guard.
    ///
    /// Parks forever once the writer is gone or a mutation was interrupted.
    pub async fn read(&self) -> ReadGuard<'_, T> {
        self.0.read().await
    }
}

/// Must cover exactly one storage call, never an application await, so a waiting mutation is
/// delayed by at most one call.
pub struct ReadGuard<'a, T>(AsyncRwLockReadGuard<'a, T>);

impl<T> Deref for ReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
    use commonware_utils::channel::oneshot;
    use futures::FutureExt as _;
    use std::{sync::atomic::AtomicUsize, time::Duration};

    /// A waiting mutation cannot be starved by a stream of overlapping reads,
    /// and no read ever observes taken-out state.
    #[test]
    fn mutation_is_not_starved_by_read_storm() {
        deterministic::Runner::default().start(|context| async move {
            let (writer, reader) = split(0u64);

            let mut workers = Vec::new();
            for (worker, offset) in [("r0", 0), ("r1", 1), ("r2", 2), ("r3", 3)] {
                let reader = reader.clone();
                workers.push(context.child(worker).spawn(move |ctx| async move {
                    ctx.sleep(Duration::from_micros(offset * 250)).await;
                    loop {
                        // Hold each guard across an await, so some guard is
                        // always granted while the mutation waits.
                        let guard = reader.read().await;
                        assert!(*guard == 0 || *guard == 1);
                        if *guard == 1 {
                            return;
                        }
                        ctx.sleep(Duration::from_millis(1)).await;
                        drop(guard);
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

            for worker in workers {
                worker.await.expect("worker should observe the mutation");
            }
        });
    }

    /// A read waits out an in-flight mutation and then sees the mutated
    /// state, never a gap.
    #[test]
    fn reads_wait_out_a_parked_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let (writer, reader) = split(0u64);
            let (release_tx, release) = oneshot::channel::<()>();
            let (acquired_tx, acquired) = oneshot::channel::<()>();

            let mutation_task = context.child("mutation").spawn(move |_| async move {
                let (writer, ()) = writer
                    .mutate(|db| async move {
                        let _ = acquired_tx.send(());
                        let _ = release.await;
                        (db + 1, ())
                    })
                    .await;
                writer
            });

            acquired.await.expect("mutation must start");
            let read = reader.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a read must wait while a mutation holds the cell",
            );

            release_tx.send(()).expect("mutation is waiting");
            let _writer = mutation_task.await.expect("mutation completes");
            assert_eq!(*read.await, 1, "the read sees the mutated state");
        });
    }

    /// Dropping the writer closes the cell, and later reads park.
    #[test]
    fn dropped_writer_parks_readers() {
        deterministic::Runner::default().start(|_context| async move {
            let (writer, reader) = split(0u64);
            assert_eq!(*reader.read().await, 0);
            drop(writer);

            let read = reader.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a read after the writer drops must park, not serve frozen state",
            );
        });
    }

    /// Counts drops of the value it wraps.
    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Dropping the writer drops the database even while readers remain.
    #[test]
    fn dropped_writer_reclaims_database() {
        deterministic::Runner::default().start(|_context| async move {
            let drops = Arc::new(AtomicUsize::new(0));
            let (writer, reader) = split(DropCounter(drops.clone()));
            drop(writer);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(reader);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        });
    }

    /// A guard held when the writer drops leaves the database to the
    /// remaining readers, which drop it last.
    #[test]
    fn guard_held_at_writer_drop_defers_reclaim_to_readers() {
        deterministic::Runner::default().start(|_context| async move {
            let drops = Arc::new(AtomicUsize::new(0));
            let (writer, reader) = split(DropCounter(drops.clone()));
            let second = reader.clone();
            let guard = reader.read().await;
            drop(writer);
            drop(guard);
            drop(reader);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            drop(second);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        });
    }

    /// Dropping a mutation mid-flight poisons the cell, and later reads park.
    #[test]
    fn interrupted_mutation_parks_readers() {
        deterministic::Runner::default().start(|_context| async move {
            let (writer, reader) = split(0u64);
            let (started_tx, started) = oneshot::channel::<()>();

            let mut mutation = Box::pin(writer.mutate(|db| async move {
                let _ = started_tx.send(());
                future::pending::<()>().await;
                (db, ())
            }));
            assert!(
                mutation.as_mut().now_or_never().is_none(),
                "mutation must park mid-flight",
            );
            started.await.expect("mutation must reach its closure");
            drop(mutation);

            let read = reader.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a read after poisoning must park, not observe a gap",
            );
        });
    }
}
