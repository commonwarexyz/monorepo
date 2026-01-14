//! Voter actor for minimmit consensus.
//!
//! The Voter combines the roles of batching (vote collection and verification) and
//! consensus state machine (view management and certificate creation) into a single actor.
//!
//! # Responsibilities
//!
//! - Receive votes from network and batch verify signatures
//! - Track votes per view in a [`crate::minimmit::types::VoteTracker`]
//! - Detect M threshold (2f+1) for certificate assembly
//! - Detect L threshold (n-f) for finalization
//! - Handle nullify-by-contradiction logic
//! - Propose when leader
//! - Verify proposals from other leaders
//! - Persist state for crash recovery

#![allow(unused_imports)] // Re-exports for public API

mod actor;
mod ingress;
mod round;
mod slot;
mod state;

pub use actor::{Actor, Config};
pub use ingress::{Mailbox, Message};
pub(crate) use state::{interesting, min_active};
