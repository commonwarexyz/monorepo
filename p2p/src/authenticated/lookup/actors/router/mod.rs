mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Message, Messenger};

/// Config for an [Actor].
pub struct Config {
    pub mailbox_size: usize,
}
