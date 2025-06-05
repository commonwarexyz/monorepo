pub mod actor;
pub mod ingress;

pub use actor::Actor;
pub use ingress::{Message, Messenger};

pub struct Config {
    pub mailbox_size: usize,
}
