//! Runtime threads: OS threads owned by a runtime that run only the tasks placed on them.
//!
//! See [crate::Spawner::thread] for the model, [crate::Spawner::on] and
//! [crate::Spawner::spawn_on] for placing work, and [Local] for `!Send` tasks.

pub(crate) mod admission;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod affinity;
mod builder;
mod local;

pub(crate) use admission::ThreadInner;
pub use builder::{Cpus, Thread, ThreadBuilder, ThreadError};
pub(crate) use builder::{ThreadRuntime, validate};
pub use local::{Local, LocalHandle};
pub(crate) use local::Owner;

#[cfg(test)]
mod tests;
