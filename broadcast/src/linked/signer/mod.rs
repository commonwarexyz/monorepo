//! Signer actor for the broadcast module.
//!
//! Responsible for:
//! - Broadcasting chunks (if a sequencer
//! - Acknowledging chunks (if a validator)
//! - Managing the chain tip of each sequencer
//! - Managing acknowledgements for each sequencer and combining them into threshold signatures

mod ack_manager;
mod actor;
mod config;
mod ingress;
mod tip_manager;

pub use ack_manager::AckManager;
pub use actor::Actor;
pub use config::Config;
pub use ingress::{Mailbox, Message};
pub use tip_manager::TipManager;
