//! Shared sync types and functionality for authenticated databases.

use crate::qmdb::sync::engine::Config;
use commonware_codec::Encode;

pub mod engine;
pub(crate) use engine::Engine;

mod error;
pub use error::{EngineError, Error};

mod gaps;
mod journal;

pub(crate) use journal::Journal;

mod database;
pub(crate) use database::{Config as DatabaseConfig, Database};

pub mod resolver;
pub(crate) use resolver::{FetchResult, Resolver};

mod target;
pub use target::Target;

mod requests;

/// A [`Resolver`] whose associated types match a specific `Database`.
///
/// Blanket-impled for any matching `Resolver`, so callers never implement this directly.
pub trait DbResolver<DB: Database>:
    Resolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>
{
}

impl<DB, R> DbResolver<DB> for R
where
    DB: Database,
    R: Resolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>,
{
}

/// Create/open a database and sync it to a target state
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
