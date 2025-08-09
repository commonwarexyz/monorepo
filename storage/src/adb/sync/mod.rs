//! Shared sync types and functionality for authenticated databases.

pub mod engine;
use commonware_codec::Encode;
pub use engine::Engine;
mod error;
pub use error::Error;
mod gaps;
mod journal;
pub use journal::Journal;
mod verifier;
pub use verifier::{extract_pinned_nodes, verify_proof};
mod database;
pub use database::Database;
pub mod resolver;
mod target;
use crate::adb::sync::engine::EngineConfig;
pub use target::Target;
pub(super) mod requests;

pub async fn sync<DB, R>(config: EngineConfig<DB, R>) -> Result<DB, Error<DB::Error, R::Error>>
where
    DB: Database,
    DB::Op: Encode,
    R: resolver::Resolver<Op = DB::Op, Digest = DB::Digest>,
{
    Engine::new(config).await?.sync().await
}
