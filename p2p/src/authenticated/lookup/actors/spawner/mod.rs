use std::num::NonZeroUsize;

mod actor;

pub use actor::Actor;

/// Messages processed by the spawner [Actor], carrying this protocol's reservations.
pub type Message<Si, St, P> =
    crate::authenticated::spawner::Message<Si, St, P, super::tracker::Reservation<P>>;

/// Configuration for the spawner [Actor].
pub struct Config {
    pub mailbox_size: NonZeroUsize,
    pub send_batch_size: NonZeroUsize,
    /// The frequency at which a peer pings its peers to check connectivity.
    pub ping_frequency: std::time::Duration,
}
