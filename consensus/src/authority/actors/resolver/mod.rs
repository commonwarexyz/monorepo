mod actor;
mod ingress;

use crate::Automaton;
pub use actor::Actor;
pub use ingress::{Mailbox, Message};

pub struct Config<A: Automaton> {
    pub application: A,

    pub max_fetch_count: u64,
    pub max_fetch_size: usize,
}
