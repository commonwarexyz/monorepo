//! Shared sync types and functionality for authenticated databases.

use crate::adb::sync::engine::Config;
use commonware_codec::Encode;

pub mod engine;
pub(crate) use engine::Engine;

mod error;
pub use error::Error;

mod gaps;
mod journal;

pub(crate) use journal::Journal;

mod database;
pub(crate) use database::Database;

pub mod resolver;

mod target;
pub use target::Target;

mod requests;

/// Create/open a database and sync it to a target state
pub async fn sync<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, Error<DB::Error, R::Error, DB::Digest>>
where
    DB: Database,
    DB::Op: Encode,
    R: resolver::Resolver<Op = DB::Op, Digest = DB::Digest>,
{
    Engine::new(config).await?.sync().await
}
