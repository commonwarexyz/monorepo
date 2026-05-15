mod actor;
mod ingress;

use std::num::NonZeroUsize;

pub use actor::Actor;
pub use ingress::{Message, Messenger};

/// Config for an [Actor].
pub struct Config {
    pub mailbox_size: NonZeroUsize,
}
