//! A [`Gate`] owns a database. Only the gate can mutate it, and the gate
//! hands out cloneable [`Reader`]s that can only read it.
//!
//! Both sides go through a [`TracedAsyncRwLock`], which is fair and
//! write-preferring. A waiting mutation blocks later reads and cannot be
//! starved, while reads already granted finish first.
//!
//! A mutation that is interrupted poisons the gate and destroys the [`Gate`]
//! value with it, so a second mutation cannot even be written. That only
//! happens when the owning task is torn down or the mutation panics, both
//! fatal, so a reader that finds the gate poisoned logs a warning and waits
//! forever for its own teardown rather than see a missing database.
//!
//! The lock is not reentrant. Never hold a read guard while acquiring another
//! on the same gate, or a mutation queued between the two will deadlock both.

use commonware_utils::sync::{AsyncRwLockReadGuard, TracedAsyncRwLock};
use futures::future;
use std::{future::Future, sync::Arc};
use tracing::warn;

enum State<T> {
    Live(T),
    /// A mutation was interrupted before restoring the database. Fatal.
    Poisoned,
}

/// Wraps a database and hands out [`Reader`]s.
/// [`mutate`](Self::mutate) is the only way to mutate the database.
pub struct Gate<T>(Arc<TracedAsyncRwLock<State<T>>>);

/// Cloneable reader for a [`Gate`]d database.
pub struct Reader<T>(Arc<TracedAsyncRwLock<State<T>>>);

impl<T> Clone for Reader<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Acquire a read guard, waiting forever if the [`Gate`] is poisoned.
async fn read<T>(lock: &TracedAsyncRwLock<State<T>>) -> AsyncRwLockReadGuard<'_, T> {
    let guard = lock.read().await;
    match AsyncRwLockReadGuard::try_map(guard, |state| match state {
        State::Live(db) => Some(db),
        State::Poisoned => None,
    }) {
        Ok(guard) => guard,
        Err(guard) => {
            // Waiting forever is silent, so say why first.
            drop(guard);
            warn!("database gate poisoned by an interrupted mutation, parking this read");
            future::pending().await
        }
    }
}

impl<T> Gate<T> {
    /// Wrap `db` in a new gate.
    pub fn new(db: T) -> Self {
        Self(Arc::new(TracedAsyncRwLock::new(
            "database_gate",
            State::Live(db),
        )))
    }

    /// Acquire a read guard.
    pub async fn read(&self) -> AsyncRwLockReadGuard<'_, T> {
        read(&self.0).await
    }

    /// Create a [`Reader`] of the gated database.
    pub fn reader(&self) -> Reader<T> {
        Reader(self.0.clone())
    }

    /// Run a mutation on the database, returning the gate on completion.
    /// Dropping the future or panicking poisons the gate and destroys it.
    pub async fn mutate<F, Fut, R>(self, mutation: F) -> (Self, R)
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = (T, R)>,
    {
        let mut guard = self.0.write().await;
        let State::Live(db) = std::mem::replace(&mut *guard, State::Poisoned) else {
            unreachable!("a gate only exists while its state is live");
        };
        let (db, result) = mutation(db).await;
        *guard = State::Live(db);
        drop(guard);
        (self, result)
    }
}

impl<T> Reader<T> {
    /// Acquire a read guard.
    pub async fn read(&self) -> AsyncRwLockReadGuard<'_, T> {
        read(&self.0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
    use commonware_utils::channel::oneshot;
    use futures::{FutureExt as _, future};
    use std::time::Duration;

    /// Mutations run back to back, and the gate and its readers see each
    /// result.
    #[test]
    fn mutations_chain() {
        deterministic::Runner::default().start(|_context| async move {
            let gate = Gate::new(0u64);
            let reader = gate.reader();

            let (gate, ()) = gate.mutate(|db| async move { (db + 1, ()) }).await;
            let (gate, seen) = gate.mutate(|db| async move { (db + 1, db) }).await;
            assert_eq!(seen, 1, "the second mutation starts from the first");
            assert_eq!(*gate.read().await, 2);
            assert_eq!(*reader.read().await, 2);
        });
    }

    /// A steady stream of reads cannot starve a waiting mutation.
    #[test]
    fn mutation_is_not_starved_by_read_storm() {
        deterministic::Runner::default().start(|context| async move {
            let gate = Gate::new(0u64);

            let mut readers = Vec::new();
            for worker in ["r0", "r1", "r2", "r3"] {
                let reader = gate.reader();
                readers.push(context.child(worker).spawn(move |ctx| async move {
                    loop {
                        if *reader.read().await == 1 {
                            return;
                        }
                        ctx.sleep(Duration::from_millis(1)).await;
                    }
                }));
            }

            context.sleep(Duration::from_millis(5)).await;
            gate.mutate(|db| async move {
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
            let gate = Gate::new(0u64);
            let reader = gate.reader();
            let (release_tx, release) = oneshot::channel::<()>();
            let (acquired_tx, acquired) = oneshot::channel::<()>();

            let writer = context.child("writer").spawn(move |_| async move {
                gate.mutate(|db| async move {
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
                "a read must wait while a mutation holds the gate",
            );

            release_tx.send(()).expect("mutation is waiting");
            writer.await.expect("mutation completes");
            assert_eq!(*read.await, 1, "the read sees the mutated state");
        });
    }

    /// Dropping a mutation partway through poisons the gate and destroys it,
    /// so no second mutation can exist. A later read waits forever instead
    /// of seeing missing state.
    #[test]
    fn interrupted_mutation_poisons() {
        deterministic::Runner::default().start(|_context| async move {
            let gate = Gate::new(0u64);
            let reader = gate.reader();
            let (started_tx, started) = oneshot::channel::<()>();

            let mut mutation = Box::pin(gate.mutate(|db| async move {
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

            let read = reader.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a read after poisoning must wait, not see a gap",
            );
        });
    }
}
