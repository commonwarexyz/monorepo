use super::{Context, View};
use crate::{Automaton, Committer, Relay, ThresholdSupervisor};
use commonware_cryptography::{bls12381::primitives::group, Hasher, Scheme};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

/// Configuration for the consensus engine.
pub struct Config<
    C: Scheme,
    H: Hasher,
    A: Automaton<H, Context = Context>,
    R: Relay<H>,
    F: Committer<H>,
    S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Hashing algorithm.
    pub hasher: H,

    /// Automaton for the consensus engine.
    pub automaton: A,

    /// Relay for the consensus engine.
    pub relay: R,

    /// Committer for the consensus engine.
    pub committer: F,

    /// Supervisor for the consensus engine.
    pub supervisor: S,

    /// Prometheus metrics registry.
    pub registry: Arc<Mutex<Registry>>,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: usize,

    /// Prefix for all signed messages to prevent replay attacks.
    pub namespace: Vec<u8>,

    /// Number of views to replay concurrently during startup.
    pub replay_concurrency: usize,

    /// Amount of time to wait for a leader to propose a payload
    /// in a view.
    pub leader_timeout: Duration,

    /// Amount of time to wait for a quorum of notarizations in a view
    /// before attempting to skip the view.
    pub notarization_timeout: Duration,

    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub nullify_retry: Duration,

    /// Number of views behind finalized tip to track
    /// activity derived from validator messages.
    pub activity_timeout: View,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Maximum number of notarizations/nullifications to request/respond with at once.
    pub max_fetch_count: usize,

    /// Maximum number of bytes to respond with at once.
    pub max_fetch_size: usize,

    /// Maximum rate of requests to send to a given peer.
    ///
    /// Inbound rate limiting is handled by `commonware-p2p`.
    pub fetch_rate_per_peer: Quota,

    /// Number of concurrent requests to make at once.
    pub fetch_concurrent: usize,
}

impl<
        C: Scheme,
        H: Hasher,
        A: Automaton<H, Context = Context>,
        R: Relay<H>,
        F: Committer<H>,
        S: ThresholdSupervisor<Seed = group::Signature, Index = View, Share = group::Share>,
    > Config<C, H, A, R, F, S>
{
    /// Assert enforces that all configuration values are valid.
    pub fn assert(&self) {
        assert!(
            self.leader_timeout > Duration::default(),
            "leader timeout must be greater than zero"
        );
        assert!(
            self.notarization_timeout > Duration::default(),
            "notarization timeout must be greater than zero"
        );
        assert!(
            self.leader_timeout <= self.notarization_timeout,
            "leader timeout must be less than or equal to notarization timeout"
        );
        assert!(
            self.nullify_retry > Duration::default(),
            "nullify retry broadcast must be greater than zero"
        );
        assert!(
            self.activity_timeout > 0,
            "activity timeout must be greater than zero"
        );
        assert!(
            self.fetch_timeout > Duration::default(),
            "fetch timeout must be greater than zero"
        );
        assert!(
            self.max_fetch_count > 0,
            "it must be possible to fetch at least one container per request"
        );
        assert!(
            self.max_fetch_size > 0,
            "it must be possible to fetch at least one byte"
        );
        assert!(
            self.fetch_concurrent > 0,
            "it must be possible to fetch from at least one peer at a time"
        );
        assert!(
            self.replay_concurrency > 0,
            "it must be possible to replay at least one view at a time"
        );
    }
}
