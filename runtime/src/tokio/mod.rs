//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness and storage backed by the local filesystem.
//!
//! # Panics
//!
//! Unless configured otherwise, any task panic will lead to a runtime panic.
//!
//! # Storage
//!
//! [crate::Runner::start] holds the storage directory (an advisory lock on its
//! `.hold` file) until the run's storage and every operation it dispatched have
//! finished. A start on a directory another run still holds blocks, with a
//! warning, until then. A `Context`, `Storage`, or `Blob` kept past `start`
//! keeps the hold.
//!
//! Before user code starts, Linux flushes the storage filesystem. macOS flushes
//! the storage directory, then each existing partition before its first scan or
//! open. These directory flushes make inherited partition and blob removals
//! durable before recovery observes their absence. Creation and removal
//! synchronize subsequent directory changes.
//!
//! On macOS, existing blobs are also flushed individually on their first open.
//! Directory synchronization covers names. This separate flush covers file data.
//! Both use `F_FULLFSYNC` through [`std::fs::File::sync_all`].
//!
//! Failures while synchronizing blob contents, including during
//! [SYNC](crate::WriteOptions::SYNC) writes, are retained across opens of the blob,
//! even after every handle is dropped.
//! Creation failures are retained when the header is complete. Removing or
//! recreating the blob clears its retained error. A new runtime instance starts
//! without the error record and still requires normal storage recovery.
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
