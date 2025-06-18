use governor::Quota;

pub mod actor;
pub use actor::Actor;
pub mod ingress;
pub use ingress::Mailbox;

pub struct Config {
    pub mailbox_size: usize,
    /// The frequency at which a peer pings its peers to check connectivity.
    pub ping_frequency: std::time::Duration,
    pub allowed_ping_rate: Quota,
}
