//! Shared sync types and functionality for authenticated databases.

pub mod engine;
pub use engine::Engine;
mod error;
pub use error::Error;
mod gaps;
mod journal;
pub use journal::Journal;
mod verifier;
pub use verifier::Verifier;
mod database;
pub use database::Database;
pub mod resolver;
mod target;
use crate::adb::sync::engine::EngineConfig;
pub use target::Target;
pub(super) mod requests;

pub async fn sync<DB: Database, R: resolver::Resolver<Op = DB::Op, Digest = DB::Digest>>(
    config: EngineConfig<DB, R>,
) -> Result<DB, Error<DB::Error, R::Error>> {
    Engine::new(config).await?.sync().await
}
