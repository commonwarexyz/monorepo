mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Messenger};
#[cfg(test)]
pub(crate) use ingress::Message;
use std::num::NonZeroUsize;

/// Config for an [Actor].
pub struct Config {
    pub mailbox_size: NonZeroUsize,
}
