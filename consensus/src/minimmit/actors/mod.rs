//! Actor implementations for minimmit consensus.
//!
//! Minimmit uses a 2-actor architecture:
//!
//! - [`voter`]: Combined vote collection, verification, and consensus state machine.
//!   This actor handles both the batching/verification role and the voting/consensus
//!   role that are separate in simplex.
//!
//! - [`resolver`]: Fetches missing certificates from peers when needed for
//!   view advancement.

pub mod resolver;
pub mod voter;
