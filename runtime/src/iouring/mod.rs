//! Task execution and I/O on Linux io_uring.
//!
//! [`Runner`] polls ordinary tasks and drives their I/O on its calling thread.
//! Dedicated and blocking tasks each receive a supervised thread and ring.
//! Their ordinary descendants execute on the runner's calling thread. Task
//! factories run synchronously on the thread that calls [`crate::Spawner::spawn`].
//!
//! Sockets, blobs, and pending I/O and sleep futures can move between workers.
//! Registrations stay on their original worker without keeping it alive. If it
//! closes, pending I/O futures return errors and pending sleeps panic when polled.
//! [`crate::Blob::start_sync`] handles can be awaited on another thread, even after
//! the original runner shuts down.
//!
//! # Ownership
//!
//! Workers own task, request, timer, and result progress. Each open serializes
//! durability operations across workers through their terminal accounting.
//! Forwarded results, mailboxes, task handles, supervision, and metrics are
//! synchronized across threads.
//!
//! # Storage
//!
//! Failures while synchronizing blob contents, including during
//! [SYNC](crate::WriteOptions::SYNC) writes, are retained across opens of the
//! blob, even after every handle is dropped. Creation failures are retained
//! when the header is complete. Removing or recreating the blob clears its
//! retained error. A new runtime instance starts without the error record and
//! still requires normal storage recovery.
//!
//! # Requirements and Progress
//!
//! Linux 6.1 or newer is required for single-issuer rings with deferred task
//! work. Task polls must return so their worker can service I/O and deadlines.
//!
//! Each worker limits in-flight I/O according to [`RingConfig::size`]. A receive
//! can occupy the last slot while a send needed to satisfy it waits to be
//! submitted. Use deadlines or cancellation to break such dependencies.
//!
//! # Shutdown
//!
//! On shutdown, the runner rejects new tasks and I/O, aborts supervised tasks,
//! and drains registered I/O before returning. The first poll registers an I/O
//! request with its worker. Registered storage writes and syncs run to completion
//! even if their futures are dropped while still queued. For pending reads and
//! network operations, dropping the future or closing the worker requests cancellation.
//!
//! Shutdown waits for all workers to finish runtime cleanup and failure publication,
//! with no timeout. Native thread-local destructors may run after the runner returns.
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

mod driver;
mod mailbox;
pub(crate) mod operation;
mod registration;
pub(crate) mod request;
mod runtime;
mod slab;
mod sleep;
pub(crate) mod sockaddr;
mod spinner;
mod task;
mod timeout;
mod waiter;
mod waker;

pub use runtime::{Config, Context, RingConfig, Runner};
pub use spinner::Config as SpinnerConfig;
