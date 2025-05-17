mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Message};

use crate::{threshold_simplex::types::View, Reporter, ThresholdSupervisor};
use commonware_p2p::Blocker;

pub struct Config<B: Blocker, R: Reporter, S: ThresholdSupervisor> {
    pub blocker: B,
    pub reporter: R,
    pub supervisor: S,

    pub activity_timeout: View,
    pub skip_timeout: View,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
}
