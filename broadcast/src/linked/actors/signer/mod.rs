use crate::Application;
use commonware_consensus::{threshold_simplex::View, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Share, Signature},
        poly::Public,
    },
    Hasher, Scheme,
};

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Message};

pub struct Config<
    C: Scheme,
    H: Hasher,
    A: Application,
    S: ThresholdSupervisor<Seed = Signature, Index = View, Share = Share, Identity = Public>,
> {
    pub crypto: C,
    pub hasher: H,
    pub app: A,
    pub supervisor: S,
    pub mailbox_size: usize,
    pub namespace: Vec<u8>,
}
