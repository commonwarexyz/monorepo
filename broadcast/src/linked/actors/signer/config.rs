use crate::{
    linked::{Context, View},
    Application, Collector, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};

pub struct Config<
    C: Scheme,
    H: Hasher,
    A: Application,
    Z: Collector<Context = Context, Proof = Bytes>,
    S: ThresholdCoordinator<Index = View>,
> {
    pub crypto: C,
    pub hasher: H,
    pub coordinator: S,
    pub application: A,
    pub collector: Z,
    pub mailbox_size: usize,
    pub namespace: Vec<u8>,
}
