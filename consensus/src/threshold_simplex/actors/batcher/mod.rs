mod actor;
mod ingress;

use crate::{
    types::{Epoch, View},
    Reporter, ThresholdSupervisor,
};
pub use actor::Actor;
use commonware_p2p::Blocker;
pub use ingress::{Mailbox, Message};

pub struct Config<B: Blocker, R: Reporter, S: ThresholdSupervisor> {
    pub blocker: B,
    pub reporter: R,
    pub supervisor: S,

    pub activity_timeout: View,
    pub skip_timeout: View,
    pub epoch: Epoch,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
}
