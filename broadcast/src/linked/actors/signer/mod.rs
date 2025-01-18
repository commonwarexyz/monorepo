use commonware_cryptography::{bls12381::primitives::group::Share, Hasher};

mod actor;
mod ingress;

pub use ingress::{Mailbox, Message};

pub struct Config<H: Hasher> {
    pub mailbox_size: usize,
    pub hasher: H,
    pub share: Share,
    pub namespace: Vec<u8>,
}
