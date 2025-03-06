//! Peer actor that communicates over the network.
//!
//! It is responsible for:
//! - Fetching data from other peers and notifying the `Consumer`
//! - Serving data to other peers by requesting it from the `Producer`

mod config;
mod engine;
mod fetcher;
mod ingress;
mod metrics;

pub use config::Config;
pub use engine::Engine;
pub use ingress::{Mailbox, Message};
