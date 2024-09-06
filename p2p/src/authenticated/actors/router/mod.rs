use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Messenger};

pub struct Config {
    pub registry: Arc<Mutex<Registry>>,
    pub mailbox_size: usize,
}
