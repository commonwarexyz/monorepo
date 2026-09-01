//! Durable storage adapters for one Multimmit engine.
//!
//! These adapters execute storage work selected by the local state machine. They do not choose
//! protocol transitions, derive replacement effects, or release work before its write barrier is
//! durable. [`recover`] reopens them at startup and rebuilds the machine before any actor starts.

#[cfg(all(feature = "mocks", not(target_arch = "wasm32")))]
pub(crate) mod bench;
mod journal;
mod recovery;
mod snapshot;

pub use journal::JournalError;
pub(crate) use journal::{Config as JournalConfig, JournalRecord, SafetyJournal};
#[cfg(test)]
pub(crate) use recovery::partitions;
pub use recovery::{CoreInitializationError, OpenError};
pub(crate) use recovery::{Recovered, RecoveryConfig, recover, valid_partition_prefix};
pub use snapshot::SnapshotError;
pub(crate) use snapshot::SnapshotStore;
