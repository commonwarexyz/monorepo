use super::{
    elector::Config as Elector,
    types::{Activity, Context},
};
use crate::{
    types::{Epoch, ViewDelta},
    Automaton, Relay, Reporter,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_runtime::buffer::PoolRef;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the minimmit consensus engine.
///
/// Minimmit requires n >= 5f + 1 participants for Byzantine fault tolerance,
/// where f is the maximum number of Byzantine replicas.
pub struct Config<
    S: Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
> {
    /// Namespace for domain separation in signatures.
    ///
    /// This namespace is prepended to all signed messages to prevent cross-protocol
    /// signature reuse attacks. Each deployment should use a unique namespace.
    pub namespace: Vec<u8>,

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
    ///
    /// Unlike simplex which requires [`CertifiableAutomaton`], minimmit only needs the base
    /// [`Automaton`] trait since there is no separate certification phase.
    pub automaton: A,

    /// Relay for the consensus engine.
    pub relay: R,

    /// Reporter for the consensus engine.
    ///
    /// All activity is exported for downstream applications that benefit from total observability.
    pub reporter: F,

    /// Partition for the consensus engine.
    pub partition: String,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: usize,

    /// Epoch for the consensus engine. Each running engine should have a unique epoch.
    pub epoch: Epoch,

    /// Number of bytes to buffer when replaying during startup.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer to use for each blob in the journal.
    pub write_buffer: NonZeroUsize,

    /// Buffer pool for the journal.
    pub buffer_pool: PoolRef,

    /// Amount of time to wait for a leader to propose a payload in a view.
    ///
    /// Per the minimmit specification, this is typically set to 2*Delta where
    /// Delta is the maximum network delay after GST.
    pub leader_timeout: Duration,

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
        A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
        R: Relay,
        F: Reporter<Activity = Activity<S, D>>,
    > Config<S, L, B, D, A, R, F>
{
    /// Assert enforces that all configuration values are valid.
    ///
    /// This includes verifying the minimmit requirement that n >= 5f + 1
    /// for Byzantine fault tolerance.
    pub fn assert(&self) {
        let n = self.scheme.participants().len();

        // Minimmit requires n >= 5f + 1, which means f = (n-1)/5
        // Minimum viable is n = 5 (f = 0, but this is degenerate)
        // Practical minimum is n = 6 (f = 1)
        assert!(
            n >= 5,
            "minimmit requires at least 5 participants (n >= 5f + 1)"
        );

        // Warn about degenerate configurations with no fault tolerance
        if n < 6 {
            tracing::warn!(
                n,
                "minimmit with n={} provides no Byzantine fault tolerance (f=0). \
                 Minimum n=6 is recommended for production use.",
                n
            );
        }

        assert!(
            self.leader_timeout > Duration::default(),
            "leader timeout must be greater than zero"
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

    /// Returns the number of participants in the consensus.
    pub fn participants(&self) -> usize {
        self.scheme.participants().len()
    }

    /// Returns the maximum number of Byzantine replicas that can be tolerated.
    pub fn f(&self) -> usize {
        crate::minimmit::calculate_f(self.participants())
    }

    /// Returns the M quorum threshold (2f + 1) for creating certificates.
    pub fn m_quorum(&self) -> usize {
        crate::minimmit::m_quorum(self.participants())
    }

    /// Returns the L quorum threshold (n - f) for finalization.
    pub fn l_quorum(&self) -> usize {
        crate::minimmit::l_quorum(self.participants())
    }
}
