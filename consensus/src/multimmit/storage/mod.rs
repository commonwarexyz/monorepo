//! Durable storage adapters for one attached Multimmit engine.
//!
//! These adapters execute storage work selected by the local state machine. They do not choose
//! protocol transitions, derive replacement effects, or release work before its write barrier is
//! durable.

mod checkpoint;
mod journal;

pub use checkpoint::CheckpointError;
pub(crate) use checkpoint::{CheckpointStore, Recovered};
pub use journal::Error as JournalError;
pub(crate) use journal::{Config as JournalConfig, SafetyJournal};
