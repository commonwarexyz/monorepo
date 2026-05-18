mod actor;
mod ingress;

pub use actor::Actor;
#[cfg(test)]
pub(crate) use ingress::Message;
pub use ingress::{Mailbox, Messenger};
use std::num::NonZeroUsize;

/// Config for an [Actor].
pub struct Config {
    pub mailbox_size: NonZeroUsize,
}
