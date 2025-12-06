use governor::Quota;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

/// Configuration for the spawner [Actor].
pub struct Config {
    pub mailbox_size: usize,
    /// The frequency at which a peer pings its peers to check connectivity.
    pub ping_frequency: std::time::Duration,
    pub allowed_ping_rate: Quota,
    /// Whether to rate limit outbound messages using the same rate as inbound.
    /// When enabled, outbound messages are delayed if they exceed the per-channel rate limit,
    /// preventing the remote peer from rate limiting us.
    pub rate_limit_outbound: bool,
}
