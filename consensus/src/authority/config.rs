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

impl<C: Scheme, H: Hasher, A: Automaton<Context = Context>, S: Supervisor<Index = View>>
    Config<C, H, A, S>
{
    /// Assert enforces that all configuration values are valid.
    pub fn assert(&self) {
        assert!(self.leader_timeout > Duration::default());
        assert!(self.notarization_timeout > Duration::default());
        assert!(self.nullify_retry > Duration::default());
        assert!(self.activity_timeout > 0);
        assert!(self.fetch_timeout > Duration::default());
        assert!(
            self.max_fetch_count > 0,
            "it must be possible to fetch at least one container per request"
        );
        assert!(self.max_fetch_size > 0);
        assert!(self.fetch_concurrent > 0);
        assert!(self.replay_concurrency > 0);
    }
}
