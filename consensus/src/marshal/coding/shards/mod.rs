//! Shard engine for erasure-coded block distribution and reconstruction.
//!
//! # Overview
//!
//! The shards subsystem distributes erasure-coded blocks, validates shard authenticity, and
//! reconstructs blocks on demand. It ensures every validator contributes bandwidth proportional
//! to a single shard while allowing any node to recover the entire [`super::types::CodedBlock`]
//! once enough shards are available.
//!
//! # Responsibilities
//!
//! - [`Engine`] accepts commands over [`Mailbox`] to broadcast proposer shards, validate and
//!   reshare received shards, and serve reconstruction requests.
//! - Retains reconstruction state and reconstructed blocks in a bounded window of commitment
//!   records. Records with the lowest rounds are evicted first.
//! - Tracks subscriptions for shard arrival and block reconstruction, notifying waiters when
//!   data becomes available.

mod mailbox;
pub use mailbox::Mailbox;

mod metrics;

mod engine;
pub use engine::{Config, Engine, Error};
