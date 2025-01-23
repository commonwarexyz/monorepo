use crate::Application;
use commonware_consensus::{threshold_simplex::View, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Share, Signature},
        poly::Public,
    },
    Hasher, Scheme,
};

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
    pub share: Share,
    pub namespace: Vec<u8>,
}

impl<
        C: Scheme,
        H: Hasher,
        A: Application,
        S: ThresholdSupervisor<Seed = Signature, Index = View, Share = Share, Identity = Public>,
    > Config<C, H, A, S>
{
    pub fn assert(&self) {}
}
