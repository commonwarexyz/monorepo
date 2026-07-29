//! Shared sync types and functionality for authenticated databases.

use crate::qmdb::sync::engine::Config;
use commonware_codec::Encode;
use commonware_macros::boxed;

pub mod engine;
pub(crate) use engine::Engine;

mod error;
pub use error::{EngineError, Error, ServeError};

mod gaps;
mod journal;
pub(crate) use journal::Journal;

mod metrics;
pub use metrics::Metrics;

mod database;
pub(crate) use database::{
    Config as DatabaseConfig, Database, journal_covers_range, local_pinned_nodes,
};

pub mod resolver;
pub(crate) use resolver::Source;

mod target;
pub use target::Target;

pub mod compact;
mod requests;

/// A [`Source`] of operations whose associated types match a specific `Database`.
///
/// Blanket-impled for any matching `Source`, so callers never implement this directly.
/// `Clone` and `'static` are required by the engine, which clones the source once per
/// in-flight request; they are not required of sources in general.
pub trait DbResolver<DB: Database>:
    Source<resolver::Request<DB::Family>, Family = DB::Family, Op = DB::Op, Digest = DB::Digest>
    + Clone
    + 'static
{
}

impl<DB, R> DbResolver<DB> for R
where
    DB: Database,
    R: Source<resolver::Request<DB::Family>, Family = DB::Family, Op = DB::Op, Digest = DB::Digest>
        + Clone
        + 'static,
{
}

/// Create/open a database and sync it to a target state
#[boxed]
pub async fn sync<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    DB::Op: Encode,
    R: DbResolver<DB>,
{
    Engine::new(config).await?.sync().await
}
