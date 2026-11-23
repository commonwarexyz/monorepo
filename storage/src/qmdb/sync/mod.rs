//! Shared sync types and functionality for authenticated databases.
//!
//! # Trust Model
//!
//! Sources are untrusted, and their responses are verified against the requested target. The
//! target itself is a trusted input chosen by the caller: sync does not select or authenticate it.
//!
//! Target updates form a forward-only sequence. Sync adopts only strictly advancing targets and
//! discards the rest. Selecting a single target before this boundary lets sync focus on fetching
//! and verifying its data instead of reconciling competing targets.

use commonware_macros::boxed;

pub(crate) mod engine;
pub use engine::Config;
pub(crate) use engine::Engine;

mod error;
pub use error::{EngineError, Error, ServeError};

mod gaps;
pub(crate) mod journal;
pub(crate) use journal::Journal;

#[cfg(test)]
pub(crate) mod harness;

mod metrics;
pub use metrics::Metrics;

mod database;
pub(in crate::qmdb) use database::Hooks;
pub(crate) use database::{Config as DatabaseConfig, local_pinned_nodes};
pub use database::{Database, MerkleizedBatch};

pub mod source;
pub use source::{Feedback, Request, Response, ResponseOf, Source, max_response_size};

mod target;
pub use target::Target;

mod requests;

/// A [`Source`] of operations for the given database.
pub trait SourceFor<DB: Database>:
    Source<Family = DB::Family, Op = DB::Op, Digest = DB::Digest> + 'static
{
}

impl<DB, S> SourceFor<DB> for S
where
    DB: Database,
    S: Source<Family = DB::Family, Op = DB::Op, Digest = DB::Digest> + 'static,
{
}

/// Create or open a database and sync it to the target in `config`.
///
/// Local operations must belong to the same canonical history as the target. After an
/// interruption, ordinary initialization can reopen at a retained commit, including one
/// short of the target. It can fail if sync reset or truncated history needed for recovery.
/// To finish a pending sync, call this function again with the trusted target.
#[boxed]
pub async fn sync<DB, S>(
    config: Config<DB, S>,
) -> Result<DB, Error<DB::Family, S::Error, DB::Digest>>
where
    DB: Database,
    S: SourceFor<DB>,
{
    Engine::new(config).await?.sync().await
}
