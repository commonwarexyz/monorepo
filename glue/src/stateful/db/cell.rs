//! Separates read access to a live database from the authority to mutate it.
//!
//! [`gate`] wraps a database and returns two capabilities over it. The
//! [`Mutator`] is unique and runs consuming mutations. The [`ReadHandle`] is
//! freely cloned into batches, and grants short leases that cover exactly one
//! storage call.
//!
//! Neither value owns the database. The gate does, and both capabilities keep
//! it alive. What distinguishes them is what they permit.
//!
//! The gate is a tokio read-write lock, whose documented policy is fair and
//! write-preferring: a waiting mutation blocks later leases and cannot be
//! starved, while leases already granted finish first. The write side covers
//! the whole take-and-restore of a mutation, so a reader can never observe the
//! database missing. A mutation that is interrupted mid-flight leaves the gate
//! poisoned, and the only thing that interrupts one here is the owning task
//! being torn down, so later leases park forever and are dropped along with
//! the tasks holding them.
//!
//! Two rules keep callers out of trouble. The lock is not reentrant, so never
//! hold a lease while acquiring another on the same gate: a mutation queued
//! between the two would deadlock both. And a [`Mutator`] must outlive the
//! handles from the same gate, because it is not what keeps the database
//! alive: readers would go on answering from a database that can never
//! advance.

use commonware_utils::sync::{AsyncRwLockReadGuard, TracedAsyncRwLock};
use futures::future;
use std::{future::Future, ops::Deref, sync::Arc};

enum State<T> {
    Live(T),
    /// A mutation was interrupted before restoring the database. Fatal.
    Poisoned,
}

struct Gate<T> {
    state: TracedAsyncRwLock<State<T>>,
}

/// Wrap `db`, returning the sole mutation authority and a cloneable read
/// capability.
pub fn gate<T>(db: T) -> (Mutator<T>, ReadHandle<T>) {
    let gate = Arc::new(Gate {
        state: TracedAsyncRwLock::new("database_gate", State::Live(db)),
    });
    (Mutator(gate.clone()), ReadHandle(gate))
}

/// The unique capability to mutate the gated database.
///
/// This is the only value with [`mutate`](Self::mutate), and it is deliberately
/// not [`Clone`], so at most one exists per gate. It does not own the database:
/// dropping it leaves readers on a database that can no longer advance, which is
/// why it must outlive the handles taken from the same gate.
pub struct Mutator<T>(Arc<Gate<T>>);

/// A cloneable read capability over the gated database.
pub struct ReadHandle<T>(Arc<Gate<T>>);

impl<T> Clone for ReadHandle<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// A short read lease. Must cover exactly one storage call, never an
/// application await, so a waiting mutation is delayed by at most one call.
pub struct ReadLease<'a, T>(AsyncRwLockReadGuard<'a, T>);

impl<T> Deref for ReadLease<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> Gate<T> {
    async fn read(&self) -> ReadLease<'_, T> {
        let guard = self.state.read().await;
        match AsyncRwLockReadGuard::try_map(guard, |state| match state {
            State::Live(db) => Some(db),
            State::Poisoned => None,
        }) {
            Ok(lease) => ReadLease(lease),
            Err(guard) => {
                // Poisoning is only reachable during mutator teardown. Park until
                // this task is dropped with the rest of the actor.
                drop(guard);
                future::pending().await
            }
        }
    }
}

impl<T> ReadHandle<T> {
    /// Acquire a read lease.
    pub async fn read(&self) -> ReadLease<'_, T> {
        self.0.read().await
    }
}

impl<T> Mutator<T> {
    /// Run one consuming mutation to completion, returning the capability.
    ///
    /// New leases queue behind the mutation and leases already granted finish
    /// first, so this waits at most one storage call before starting.
    ///
    /// Consume/produce at both levels. `mutation` takes the database by value and
    /// must produce it back, which is the contract mutable storage operations
    /// already use. This method does the same with the capability, so an
    /// interrupted mutation takes the mutator with it: dropping this future
    /// leaves the gate poisoned and hands nothing back, which is what makes a
    /// second mutation of a poisoned gate unreachable rather than merely
    /// documented. Leases taken afterward park forever.
    pub async fn mutate<F, Fut, R>(self, mutation: F) -> (Self, R)
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = (T, R)>,
    {
        let mut guard = self.0.state.write().await;
        let State::Live(db) = std::mem::replace(&mut *guard, State::Poisoned) else {
            unreachable!("a mutator only exists while its gate is live")
        };
        let (db, result) = mutation(db).await;
        *guard = State::Live(db);
        drop(guard);
        (self, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Clock, Runner as _, Spawner as _, Supervisor as _, deterministic};
    use commonware_utils::channel::oneshot;
    use futures::FutureExt as _;
    use std::time::Duration;

    /// A waiting mutation cannot be starved by a stream of short read leases,
    /// and no lease ever observes taken-out state.
    #[test]
    fn mutation_is_not_starved_by_read_storm() {
        deterministic::Runner::default().start(|context| async move {
            let (mutator, handle) = gate(0u64);

            let mut readers = Vec::new();
            for worker in ["r0", "r1", "r2", "r3"] {
                let handle = handle.clone();
                readers.push(context.child(worker).spawn(move |ctx| async move {
                    loop {
                        {
                            let lease = handle.read().await;
                            // Every observation is a full, live value.
                            assert!(*lease == 0 || *lease == 1);
                            if *lease == 1 {
                                return;
                            }
                        }
                        ctx.sleep(Duration::from_millis(1)).await;
                    }
                }));
            }

            context.sleep(Duration::from_millis(5)).await;
            mutator
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

    /// A lease waits out an in-flight mutation and then sees the mutated
    /// state, never a gap.
    #[test]
    fn leases_wait_out_a_parked_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let (mutator, handle) = gate(0u64);
            let (release_tx, release) = oneshot::channel::<()>();
            let (acquired_tx, acquired) = oneshot::channel::<()>();

            let writer = context.child("writer").spawn(move |_| async move {
                mutator
                    .mutate(|db| async move {
                        let _ = acquired_tx.send(());
                        let _ = release.await;
                        (db + 1, ())
                    })
                    .await;
            });

            acquired.await.expect("mutation must start");
            let read = handle.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a lease must wait while a mutation holds the gate",
            );

            release_tx.send(()).expect("mutation is waiting");
            writer.await.expect("mutation completes");
            assert_eq!(*read.await, 1, "the lease sees the mutated state");
        });
    }

    /// Dropping a mutation mid-flight poisons the gate, and takes the mutator
    /// with it. Later leases park forever instead of observing missing state.
    /// A second mutation is unrepresentable, so there is nothing to assert.
    #[test]
    fn interrupted_mutation_poisons() {
        deterministic::Runner::default().start(|_context| async move {
            let (mutator, handle) = gate(0u64);
            let (started_tx, started) = oneshot::channel::<()>();

            let mut mutation = Box::pin(mutator.mutate(|db| async move {
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

            let read = handle.read();
            futures::pin_mut!(read);
            assert!(
                read.as_mut().now_or_never().is_none(),
                "a lease after poisoning must park, not observe a gap",
            );
        });
    }
}
