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

use crate::qmdb::sync::engine::Config;
use commonware_codec::Encode;
use commonware_macros::boxed;

pub mod engine;
pub(crate) use engine::Engine;

mod error;
pub use error::{EngineError, Error, ServeError};

mod gaps;
pub(crate) mod journal;
pub(crate) use journal::Journal;

mod metrics;
pub use metrics::Metrics;

mod database;
pub use database::Database;
pub(crate) use database::{Config as DatabaseConfig, journal_covers_range, local_pinned_nodes};

pub mod source;
pub use source::{FeedbackTx, Request, Response, Source};

mod target;
pub use target::{CompactTarget, Target};

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

/// Create/open a database and sync it to a target state
#[boxed]
pub async fn sync<DB, S>(
    config: Config<DB, S>,
) -> Result<DB, Error<DB::Family, S::Error, DB::Digest>>
where
    DB: Database,
    DB::Op: Encode,
    S: SourceFor<DB>,
{
    Engine::new(config).await?.sync().await
}
