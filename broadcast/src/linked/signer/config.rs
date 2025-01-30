use std::time::Duration;

use crate::{
    linked::{Context, Epoch},
    Application, Collector, ThresholdCoordinator,
};
use commonware_cryptography::{Hasher, PublicKey, Scheme};

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
    pub refresh_epoch_timeout: Duration,
    pub rebroadcast_timeout: Option<Duration>,
    pub epoch_bounds: (u64, u64),
    pub journal_naming_fn: fn(&PublicKey) -> String,
    pub journal_entries_per_section: u64,
    pub journal_replay_concurrency: usize,
}
