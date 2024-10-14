use crate::{Parser, Processor, View};
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use prometheus_client::registry::Registry;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct Config<C: Scheme, Pa: Parser, Pr: Processor> {
    pub crypto: C,
    pub parser: Pa,
    pub processor: Pr,

    pub registry: Arc<Mutex<Registry>>,

    pub namespace: Bytes,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub null_vote_retry: Duration,

    /// Timeout to wait for a peer to respond to a fetch request.
    pub fetch_timeout: Duration,

    /// Maximum number of blocks to request/respond with in a single fetch.
    pub max_fetch_count: u64,

    /// Maximum number of bytes to respond with in a single fetch.
    pub max_fetch_size: usize,

    /// Validators to use for each range of views. Any view without
    /// an explicit view will use the next smallest view.
    pub validators: BTreeMap<View, Vec<PublicKey>>,
}
