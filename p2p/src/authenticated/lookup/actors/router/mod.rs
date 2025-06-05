pub mod actor;
pub mod ingress;

pub use actor::Actor;
pub use ingress::Messenger;

/// Config for an [Actor].
pub struct Config {
    pub mailbox_size: usize,
}
