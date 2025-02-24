//! Peer actor that communicates over the network.
//! 
//! It is responsible for:
//! - Fetching data from other peers and notifying the `Consumer`
//! - Serving data to other peers by requesting it from the `Producer`

pub mod actor;
pub mod config;
pub mod fetcher;
pub mod ingress;
