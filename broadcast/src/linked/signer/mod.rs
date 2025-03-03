//! Signer actor for the broadcast module.
//!
//! It is responsible for:
//! - Broadcasting nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer’s chain
//! - Recovering threshold signatures from partial signatures for each chunk
//! - Notifying other actors of new chunks and threshold signatures

mod ack_manager;
mod actor;
mod config;
mod ingress;
mod metrics;
mod tip_manager;

pub use ack_manager::AckManager;
pub use actor::Actor;
pub use config::Config;
pub use ingress::{Mailbox, Message};
pub use tip_manager::TipManager;
