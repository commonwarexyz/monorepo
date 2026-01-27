//! Network actors for Minimmit consensus.
//!
//! The consensus engine is split into three actors:
//!
//! - **Voter**: Main consensus participant that processes proposals, votes, and drives view
//!   progression.
//! - **Batcher**: Handles message batching and verification, forwarding verified messages to the
//!   voter.
//! - **Resolver**: Fetches missing certificates from peers to enable view progression.

pub mod batcher;
pub mod resolver;
pub mod voter;
