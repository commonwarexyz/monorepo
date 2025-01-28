use crate::{
    linked::{Context, Epoch},
    Application, Collector, ThresholdCoordinator,
};
use commonware_cryptography::{Hasher, Scheme};

pub struct Config<
    C: Scheme,
    H: Hasher,
    A: Application,
    Z: Collector<Context = Context>,
    S: ThresholdCoordinator<Index = Epoch>,
> {
    pub crypto: C,
    pub hasher: H,
    pub coordinator: S,
    pub application: A,
    pub collector: Z,
    pub mailbox_size: usize,
    pub namespace: Vec<u8>,
}
