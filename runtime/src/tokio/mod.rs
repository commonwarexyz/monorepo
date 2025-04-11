//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness and storage backed by the local filesystem.
//!
//! # Panics
//!
//! By default, the runtime will catch any panic and log the error. It is
//! possible to override this behavior in the configuration.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio::Executor, Metrics};
//!
//! let (executor, runtime) = Executor::default();
//! executor.start(async move {
//!     println!("Parent started");
//!     let result = runtime.with_label("child").spawn(|_| async move {
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

#[cfg(feature = "iouring")]
pub mod blob_linux; // TODO can this be less public?
#[cfg(not(feature = "iouring"))]
pub mod blob_non_linux;
