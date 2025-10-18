mod actor;
mod ingress;

use crate::{
    threshold_simplex::signing_scheme::Scheme,
    types::{Epoch, View},
    Reporter,
};
pub use actor::Actor;
use commonware_cryptography::PublicKey;
use commonware_p2p::Blocker;
use commonware_utils::set::Set;
pub use ingress::{Mailbox, Message};

pub struct Config<P: PublicKey, S: Scheme, B: Blocker, R: Reporter> {
    pub participants: Set<P>,
    pub signing: S,

    pub blocker: B,
    pub reporter: R,

    pub activity_timeout: View,
    pub skip_timeout: View,
    pub epoch: Epoch,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
}
