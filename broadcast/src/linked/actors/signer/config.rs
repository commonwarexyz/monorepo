use crate::{
    linked::{Context, Index},
    Acknowledgement, Application, ThresholdCoordinator,
};
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};

pub struct Config<
    C: Scheme,
    H: Hasher,
    A: Application,
    Z: Acknowledgement<Context = Context, Proof = Bytes>,
    S: ThresholdCoordinator<Index = Index>,
> {
    pub crypto: C,
    pub hasher: H,
    pub app: A,
    pub coordinator: S,
    pub acknowledgement: Z,
    pub mailbox_size: usize,
    pub namespace: Vec<u8>,
}
