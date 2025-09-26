//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness and storage backed by the local filesystem.
//!
//! # Panics
//!
//! By default, the runtime will catch any panic and log the error. It is
//! possible to override this behavior in the configuration.
//!
//! # Variants
//!
//! This module provides two main ways to use tokio:
//!
//! - [`Runner`]: Creates and manages its own tokio runtime instance (default behavior)
//! - [`Config::with_external_tokio`]: Configures the runtime to use an existing tokio instance
//!
//! # Example with Runner (creates own runtime)
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio, Metrics};
//!
//! let executor = tokio::Runner::default();
//! executor.start(|context| async move {
//!     println!("Parent started");
//!     let result = context.with_label("child").spawn(|_| async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! ```
//!
//! # Example with external tokio runtime
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio, Metrics};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Configure to use external tokio runtime
//!     let config = tokio::Config::default().with_external_tokio(true);
//!     let executor = tokio::Runner::new(config);
//!     
//!     tokio::task::spawn_blocking(move || {
//!         executor.start(|context| async move {
//!             println!("Parent started");
//!             let result = context.with_label("child").spawn(|_| async move {
//!                 println!("Child started");
//!                 "hello"
//!             });
//!             println!("Child result: {:?}", result.await);
//!             println!("Parent exited");
//!         })
//!     }).await.unwrap();
//! }
//! ```

mod runtime;
pub use runtime::*;
pub mod telemetry;
pub mod tracing;
