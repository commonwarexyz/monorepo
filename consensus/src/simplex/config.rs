use super::types::{Activity, Context, View};
use crate::{Automaton, Relay, Reporter, Supervisor};
use commonware_cryptography::{Digest, Signer};
use commonware_runtime::buffer::PoolRef;
use governor::Quota;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the consensus engine.
pub struct Config<
    C: Signer,
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<C::Signature, D>>,
    S: Supervisor<Index = View>,
> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Automaton for the consensus engine.
    pub automaton: A,

    /// Relay for the consensus engine.
    pub relay: R,

    /// Reporter for the consensus engine.
    pub reporter: F,

    /// Supervisor for the consensus engine.
    pub supervisor: S,

    /// Partition for consensus engine storage.
    pub partition: String,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: usize,

    /// Prefix for all signed messages to prevent replay attacks.
    pub namespace: Vec<u8>,

    /// Number of bytes to buffer when replaying during startup.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer to use for each blob in the journal.
    pub write_buffer: NonZeroUsize,

    /// Buffer pool for the journal.
    pub buffer_pool: PoolRef,

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
    /// and persist activity derived from validator messages.
    pub activity_timeout: View,

    /// Maximum number of participants to track in a single round.
    ///
    /// This is used to limit the size of notarization, nullification, and finalization messages,
    /// which include up to one signature per participant. This number can be set to a reasonably high
    /// value that we never expect to reach (it is just how many signatures we are willing to parse, not verify).
    pub max_participants: usize,

    /// Move to nullify immediately if the selected leader has been inactive
    /// for this many views.
    ///
    /// This number should be less than or equal to `activity_timeout` (how
    /// many views we are tracking).
    pub skip_timeout: View,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Maximum number of notarizations/nullifications to request/respond with at once.
    pub max_fetch_count: usize,

    /// Maximum rate of requests to send to a given peer.
    ///
    /// Inbound rate limiting is handled by `commonware-p2p`.
    pub fetch_rate_per_peer: Quota,

    /// Number of concurrent requests to make at once.
    pub fetch_concurrent: usize,
}

impl<
        C: Signer,
        D: Digest,
        A: Automaton<Context = Context<D>, Digest = D>,
        R: Relay<Digest = D>,
        F: Reporter<Activity = Activity<C::Signature, D>>,
        S: Supervisor<Index = View>,
    > Config<C, D, A, R, F, S>
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
            self.skip_timeout > 0,
            "skip timeout must be greater than zero"
        );
        assert!(
            self.skip_timeout <= self.activity_timeout,
            "skip timeout must be less than or equal to activity timeout"
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
            self.fetch_concurrent > 0,
            "it must be possible to fetch from at least one peer at a time"
        );
    }
}
