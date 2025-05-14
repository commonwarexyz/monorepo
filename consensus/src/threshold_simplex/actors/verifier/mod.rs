mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Message};

use crate::ThresholdSupervisor;

pub struct Config<S: ThresholdSupervisor> {
    pub supervisor: S,

    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
}
