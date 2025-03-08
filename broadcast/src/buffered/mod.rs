//! Best-effort broadcast to a network.
//!
//! # Design
//!
//! The core of the module is the [`Engine`]. It is responsible for:
//! - Serializing and deserializing messages
//! - Performing best-effort broadcast to all participants in the network
//! - Accepting and caching broadcasts from other participants
//! - Notifying other actors of new broadcasts
//! - Serving cached broadcasts on-demand

use std::future::Future;

use commonware_utils::Array;

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod ingress;
use ingress::{Mailbox, Message};
mod metrics;

#[cfg(test)]
pub mod mocks;

pub trait Digestible<D: Array>: Clone + Send + Sync + 'static {
    fn digest(&self) -> D;
}

pub trait Serializable: Sized + Clone + Send + Sync + 'static {
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Debug)]
pub enum Error {
    DeserializationError,
}
