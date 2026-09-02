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
