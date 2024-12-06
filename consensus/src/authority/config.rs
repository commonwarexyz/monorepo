use super::{Context, View};
use crate::{Automaton, Supervisor};
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct Config<
    C: Scheme,
    H: Hasher,
    A: Automaton<Context = Context>,
    S: Supervisor<Index = View>,
> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub supervisor: S,

    pub registry: Arc<Mutex<Registry>>,

    pub mailbox_size: usize,

    pub namespace: Bytes,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,

    /// Number of views behind finalized tip to track
    /// activity derived from validator messages.
    pub activity_timeout: View,

    /// Timeout to wait for a peer to respond to a fetch request.
    pub fetch_timeout: Duration,

    /// Maximum number of containers to request/respond with in a single fetch.
    pub max_fetch_count: usize,

    /// Maximum number of bytes to respond with in a single fetch.
    pub max_fetch_size: usize,

    /// Maximum rate of fetch requests per peer (to prevent rate limiting).
    pub fetch_rate_per_peer: Quota,

    /// Number of concurrent fetch requests to make.
    pub fetch_concurrent: usize,

    pub replay_concurrency: usize,
}
