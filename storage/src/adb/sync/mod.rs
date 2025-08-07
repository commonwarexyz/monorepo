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
pub use target::Target;
pub(super) mod requests;
