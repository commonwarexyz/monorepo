use super::{
    elector::Config as Elector,
    types::{Activity, Context},
};
use crate::{
    types::{Epoch, ViewDelta},
    CertifiableAutomaton, Relay, Reporter,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_runtime::buffer::PoolRef;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the consensus engine.
pub struct Config<
    S: Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
> {
    /// Signing scheme for the consensus engine.
    ///
    /// Consensus messages can be signed with a cryptosystem that differs from the static
    /// participant identity keys exposed in `participants`. For example, we can authenticate peers
    /// on the network with [commonware_cryptography::ed25519] keys while signing votes with shares distributed
    /// via [commonware_cryptography::bls12381::dkg] (which change each epoch). The scheme implementation is
    /// responsible for reusing the exact participant ordering carried by `participants` so that signer indices
    /// remain stable across both key spaces; if the order diverges, validators will reject votes as coming from
    /// the wrong validator.
    pub scheme: S,

    /// Leader election configuration.
    ///
    /// Determines how leaders are selected for each view. Built-in options include
    /// [`RoundRobin`](super::elector::RoundRobin) for deterministic rotation and
    /// [`Random`](super::elector::Random) for unpredictable selection using BLS
    /// threshold signatures.
    pub elector: L,

    /// Blocker for the network.
    ///
    /// Blocking is handled by [commonware_p2p].
    pub blocker: B,

    /// Automaton for the consensus engine.
    pub automaton: A,

    /// Relay for the consensus engine.
    pub relay: R,

    /// Reporter for the consensus engine.
    ///
    /// All activity is exported for downstream applications that benefit from total observability,
    /// consider wrapping with [`crate::simplex::scheme::reporter::AttributableReporter`] to
    /// automatically filter and verify activities based on scheme attributability.
    pub reporter: F,

    /// Partition for the consensus engine.
    pub partition: String,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: usize,

    /// Epoch for the consensus engine. Each running engine should have a unique epoch.
    pub epoch: Epoch,

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
    pub activity_timeout: ViewDelta,

    /// Move to nullify immediately if the selected leader has been inactive
    /// for this many recent known views (we ignore views we don't have data for).
    ///
    /// This number should be less than or equal to `activity_timeout` (how
    /// many views we are tracking below the finalized tip).
    pub skip_timeout: ViewDelta,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Number of concurrent requests to make at once.
    pub fetch_concurrent: usize,
}

impl<
        S: Scheme,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: CertifiableAutomaton<Context = Context<D, S::PublicKey>>,
        R: Relay,
        F: Reporter<Activity = Activity<S, D>>,
    > Config<S, L, B, D, A, R, F>
{
    /// Assert enforces that all configuration values are valid.
    pub fn assert(&self) {
        assert!(
            !self.scheme.participants().is_empty(),
            "there must be at least one participant"
        );
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
            !self.activity_timeout.is_zero(),
            "activity timeout must be greater than zero"
        );
        assert!(
            !self.skip_timeout.is_zero(),
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
            self.fetch_concurrent > 0,
            "it must be possible to fetch from at least one peer at a time"
        );
    }
}
