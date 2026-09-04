//! Native single-threaded execution and I/O on Linux io_uring.
//!
//! [`Runner`] polls ordinary tasks and drives their I/O on its calling thread.
//! Dedicated and blocking tasks each receive a supervised thread and ring.
//! Resources can move between workers between operations. An operation binds
//! to its current worker on first poll and stays there until completion.
//!
//! # Ownership
//!
//! ```text
//! foreign context or waker -> mailbox -> owning worker
//!                                      | tasks and local timers
//!                                      | FIFO I/O admission
//!                                      v
//!                                  io_uring driver
//!                                      |
//!                            completion -> local result
//! ```
//!
//! Local tasks, admission, timers, and ordinary results need no shared locks.
//! Mailboxes, task handles, supervision, metrics, and shared resource lifetimes
//! retain synchronization where access can cross threads. See the private
//! mechanism modules for their state transitions and cancellation invariants.
//!
//! # Requirements and Progress
//!
//! Linux 6.1 or newer is required for single-issuer rings with deferred task
//! work. A task must return from each poll so the worker can service I/O and
//! deadlines. Ring capacity bounds admitted requests, not application dependency
//! cycles. Use deadlines or cancellation when admitted operations may depend on
//! work waiting for admission.
//!
//! # Shutdown
//!
//! The runner closes admission, aborts supervised tasks, and retires kernel
//! requests before returning. Admitted writes and syncs finish even if their
//! callers are gone. Shutdown waits for accepted worker runtime cleanup and failure publication.
//! Native thread-local destruction may follow. Shutdown has no time limit.
//!
//! # Examples
//!
//! ```no_run
//! use commonware_runtime::{Runner as _, Spawner, Supervisor, iouring};
//!
//! iouring::Runner::default().start(|context| async move {
//!     let child = context.child("worker").spawn(|_| async { 42 });
//!     assert_eq!(child.await.unwrap(), 42);
//! });
//! ```

mod admission;
mod callbacks;
mod driver;
mod mailbox;
pub(crate) mod operation;
pub(crate) mod request;
mod runtime;
mod sleep;
pub(crate) mod sockaddr;
mod spinner;
mod task;
mod timeout;
mod waiter;
mod waker;

pub use runtime::{Config, Context, RingConfig, Runner};
pub use spinner::Config as SpinnerConfig;

/// Packed kernel completion identity, distinct from full-width local IDs.
type UserData = u64;

use waiter::WaiterId;
