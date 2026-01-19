mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Message, Messenger};

/// Config for an [Actor].
#[ready(0)]
pub struct Config {
    pub mailbox_size: usize,
}

use commonware_macros::ready;
