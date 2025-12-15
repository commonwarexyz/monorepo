mod ingress;
mod actor;

pub use actor::Actor;
pub use ingress::Mailbox;

use std::net::SocketAddr;

/// Configuration for the observer broadcaster.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to bind the observer port.
    pub listen_addr: SocketAddr,

    /// Maximum number of concurrent observer connections.
    pub max_observers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8001".parse().unwrap(),
            max_observers: 100,
        }
    }
}