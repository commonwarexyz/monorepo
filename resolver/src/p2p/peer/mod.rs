//! Peer actor that communicates over the network.
//!
//! It is responsible for:
//! - Fetching data from other peers and notifying the `Consumer`
//! - Serving data to other peers by requesting it from the `Producer`

mod actor;
mod config;
mod fetcher;
mod ingress;

pub use actor::Actor;
pub use config::Config;
pub use ingress::{Mailbox, Message};
