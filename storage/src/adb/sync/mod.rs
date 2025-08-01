//! Shared sync types and functionality for authenticated databases.

pub mod engine;
pub use engine::Engine;
pub mod error;
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
