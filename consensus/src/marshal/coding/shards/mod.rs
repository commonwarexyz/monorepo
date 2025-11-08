//! Erasure coding engine used by the [`Actor`](super::Actor).
//!
//! # Overview
//!
//! The shards subsystem fan-outs encoded blocks, verifies shard validity, and reconstructs block
//! payloads on demand. It sits between [`commonware_broadcast::buffered`] mailboxes and the marshal
//! actor, ensuring that every validator contributes bandwidth proportional to a single shard while
//! still allowing any node to recover the entire [`super::types::CodedBlock`] once consensus decides to
//! keep it.
//!
//! # Responsibilities
//!
//! - [`Engine`] accepts commands over [`Mailbox`] to broadcast proposer shards, reshare verified
//!   fragments from non-leaders, and serve best-effort reconstruction requests.
//! - Maintains short-lived caches of [`super::types::Shard`]s and reconstructed blocks. Finalized blocks
//!   are evicted immediately because they have been persisted by the marshal actor.
//! - Tracks subscriptions for particular commitments/indices so that verification results fan out
//!   to every waiter without re-fetching the shard from the network.
//! - Implements [`crate::Reporter`] so notarize vote traffic from consensus can trigger speculative
//!   reconstruction ahead of a notarization certificate being received.
//!
//! # Interaction with Marshal
//!
//! The marshal [`super::Actor`] drives the shard engine through [`Mailbox`]:
//! - `broadcast` sends a freshly encoded block to a specific validator set (each entry maps to one
//!   shard index).
//! - `subscribe_shard_validity` asks the engine to watch for a shard, verify it, and rebroadcast it
//!   if valid.
//! - `try_reconstruct` / `subscribe_block` provide synchronous or asynchronous APIs for retrieving a
//!   full block when enough shards have been amassed.
//! - `finalized` hints that a block has been durably stored so the engine can free memory.
//!
//! This separation keeps the marshal logic focused on ordering while the shard engine deals with
//! CPU-heavy erasure coding.

mod mailbox;
pub use mailbox::{Mailbox, Message};

mod engine;
pub use engine::{Engine, ReconstructionError};
