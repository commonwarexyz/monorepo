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

pub mod compact;
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
    Box::pin(Engine::new(config).await?.sync()).await
}

/// Sync using the existing sync journal without first probing completed local state.
///
/// Call this only after durable state above QMDB has determined that a previous
/// sync was interrupted. Normal [`sync`] can reuse boundary nodes from a
/// completed local database, but that probe is the wrong ownership path for an
/// in-progress sync journal. Fetched operations and boundary nodes are still
/// verified before they are applied.
pub async fn resume<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    DB::Op: Encode,
    R: DbResolver<DB>,
{
    Box::pin(
        Engine::new_without_local_boundary(config)
            .await?
            .sync(),
    )
    .await
}
