//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness and storage backed by the local filesystem.
//!
//! # Panics
//!
//! Unless configured otherwise, any task panic will lead to a runtime panic.
//!
//! # Storage locking
//!
//! On Unix each running runtime exclusively locks its storage directory (a
//! flock on `.logstore` inside it): two concurrent runtimes over one directory
//! fail at startup, and a leaked [Context] across an in-process restart keeps
//! the lock held.
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
