use crate::{Application, Hasher, Height, View};
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use prometheus_client::registry::Registry;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::activity::Encoder;

pub struct Config<C: Scheme, H: Hasher, A: Application> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub encoder: Encoder<C, H>,

    pub registry: Arc<Mutex<Registry>>,

    pub namespace: Bytes,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub null_vote_retry: Duration,

    /// Number of heights behind notarized tip to track
    /// activity derived from validator messages.
    pub activity_timeout: Height,

    /// Timeout to wait for a peer to respond to a fetch request.
    pub fetch_timeout: Duration,

    /// Maximum number of blocks to request/respond with in a single fetch.
    pub max_fetch_count: u64,

    /// Maximum number of bytes to respond with in a single fetch.
    pub max_fetch_size: usize,

    /// Validators to use for each range of views. Any view without
    /// an explicit view will use the next smallest view.
    ///
    /// # Warning
    ///
    /// Any disagreement on this list could result in a halt or a fork.
    pub validators: BTreeMap<View, Vec<PublicKey>>,
}
