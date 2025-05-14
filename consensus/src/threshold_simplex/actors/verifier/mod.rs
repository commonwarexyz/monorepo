mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Message};

use crate::ThresholdSupervisor;
use commonware_p2p::Blocker;

pub struct Config<B: Blocker, S: ThresholdSupervisor> {
    pub blocker: B,
    pub supervisor: S,

    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
}
