use commonware_consensus::simplex::Prover;
use commonware_cryptography::{Hasher, PublicKey, Scheme};

mod actor;
pub use actor::Application;
mod ingress;
mod supervisor;

pub struct Config<C: Scheme, H: Hasher> {
    pub hasher: H,
    pub prover: Prover<C, H>,
    pub participants: Vec<PublicKey>,
    pub mailbox_size: usize,
}
