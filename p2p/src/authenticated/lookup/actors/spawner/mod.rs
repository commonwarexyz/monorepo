use std::num::NonZeroUsize;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

/// Configuration for the spawner [Actor].
pub struct Config {
    pub mailbox_size: usize,
    pub send_batch_size: NonZeroUsize,
    /// The frequency at which a peer pings its peers to check connectivity.
    pub ping_frequency: std::time::Duration,
}
