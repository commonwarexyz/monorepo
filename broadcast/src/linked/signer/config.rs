use crate::{
    linked::{Context, Epoch},
    Application, Collector, ThresholdCoordinator,
};
use commonware_cryptography::{Array, Scheme};
use std::time::Duration;

/// Configuration when creating an `Actor`.
pub struct Config<
    C: Scheme,
    D: Array,
    A: Application<Context = Context<C::PublicKey>, Digest = D>,
    Z: Collector<Digest = D>,
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
    pub journal_name_prefix: String,
    pub journal_heights_per_section: u64,
    pub journal_replay_concurrency: usize,
}
