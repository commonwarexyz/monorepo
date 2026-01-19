mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

/// Configuration for the spawner [Actor].
#[ready(0)]
pub struct Config {
    pub mailbox_size: usize,
    /// The frequency at which a peer pings its peers to check connectivity.
    pub ping_frequency: std::time::Duration,
}

use commonware_macros::ready;
