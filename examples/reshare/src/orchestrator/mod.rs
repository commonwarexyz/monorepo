//! Consensus engine orchestrator for epoch transitions.

mod actor;
pub use actor::{Actor, Config};

mod finalization_tracker;

mod ingress;
pub use ingress::{EpochTransition, Mailbox};

mod wire;
