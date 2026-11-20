//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness and storage backed by the local filesystem.
//!
//! # Panics
//!
//! Unless configured otherwise, any task panic will lead to a runtime panic.
//! This includes panics raised while dropping a task's future or output,
//! after which a handle still awaiting the task resolves to
//! [crate::Error::Closed].
//!
//! # Storage
//!
//! [crate::Runner::start] holds the storage directory (an advisory lock on its
//! `.hold` file) until the run's storage and every operation it dispatched have
//! finished. A start on a directory another run still holds blocks, with a
//! warning, until then. A `Context`, `Storage`, or `Blob` kept past `start`
//! keeps the hold.
//!
//! Before user code starts, Linux flushes the storage filesystem. Other
//! platforms synchronize the storage directory, then each existing partition
//! before its first scan or open. These directory flushes make inherited
//! partition and blob removals durable before a scan or open observes their
//! absence. Creation and removal synchronize subsequent directory changes.
//!
//! Other platforms also flush existing blobs individually on their first open.
//! Directory synchronization covers names. This separate flush covers file
//! data. On macOS, both use `F_FULLFSYNC` through [`std::fs::File::sync_all`].
//!
//! Failures while synchronizing blob contents, including during
//! [SYNC](crate::WriteOptions::SYNC) writes, are retained across opens of the
//! blob, even after every handle is dropped. Creation failures are retained
//! when the header is complete. Removing or recreating the blob clears its
//! retained error. A new runtime instance starts without the error record and
//! still requires normal storage recovery.
//!
//! # Cooperative Budget
//!
//! This runtime installs no [`commonware_utils::coop`] budget around task
//! polls, because tokio budgets its task polls itself. Receives from
//! [`commonware_utils::channel`] channels (mpsc, oneshot, watch and ring) and
//! from actor mailboxes all spend tokio's budget, so a task fed faster than it
//! drains them yields to tokio. [`crate::Runner::start`] holds the calling
//! thread's commonware budget while it runs, so a runner started from inside
//! another executor's poll runs its root without that poll's budget and gives
//! it back when it returns.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, Supervisor, tokio, Metrics};
//!
//! let executor = tokio::Runner::default();
//! executor.start(|context| async move {
//!     println!("Parent started");
//!     let result = context.child("child").spawn(|_| async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! ```

mod runtime;
pub use runtime::*;
pub mod telemetry;
pub mod tracing;
