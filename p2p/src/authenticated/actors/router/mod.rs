mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Messenger};

pub struct Config {
    pub mailbox_size: usize,
}
