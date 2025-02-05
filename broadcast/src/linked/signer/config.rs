use crate::{
    linked::{Context, Epoch},
    Application, Collector, ThresholdCoordinator,
};
use commonware_cryptography::{Digest, PublicKey, Scheme};
use std::time::Duration;

pub struct Config<
    C: Scheme,
    D: Digest,
    J: Fn(&PublicKey) -> String,
    A: Application<Context = Context, Digest = D>,
    Z: Collector<Context = Context, Digest = D>,
    S: ThresholdCoordinator<Index = Epoch>,
> {
    pub crypto: C,
    pub coordinator: S,
    pub application: A,
    pub collector: Z,
    pub mailbox_size: usize,
    pub pending_verify_size: usize,
    pub namespace: Vec<u8>,
    pub refresh_epoch_timeout: Duration,
    pub rebroadcast_timeout: Duration,
    pub epoch_bounds: (u64, u64),
    pub height_bound: u64,
    pub journal_naming_fn: J,
    pub journal_heights_per_section: u64,
    pub journal_replay_concurrency: usize,
}
