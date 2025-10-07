//! Consensus engine orchestrator for epoch transitions.

mod actor;
pub use actor::{Actor, Config};

mod ingress;
pub use ingress::{EpochTransition, Mailbox};
