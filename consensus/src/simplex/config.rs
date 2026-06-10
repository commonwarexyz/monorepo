use super::{
    elector::Config as Elector,
    types::{Activity, Context, Finalization},
};
use crate::{
    types::{Epoch, TermLength, ViewDelta},
    CertifiableAutomaton, Epochable, Relay, Reporter, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use core::num::NonZeroUsize;
use rand_core::CryptoRngCore;
use std::time::Duration;

/// Controls whether and how the engine proactively forwards certified blocks
/// when entering the next view.
///
/// Forwarding is a best-effort liveness aid: when enabled, the batcher
/// broadcasts only after we locally certify a proposal and enter the next
/// view, avoiding sends for proposals that never pass certification.
#[derive(Debug, Clone, Copy)]
pub enum ForwardingPolicy {
    /// Do nothing when a certified proposal becomes eligible for forwarding.
    Disabled,
    /// Forward the block to all participants that did not vote for the proposal.
    ///
    /// To only send to the leader of the newly entered view, see [ForwardingPolicy::SilentLeader].
    SilentVoters,
    /// Forward the block to the leader of the newly entered view if they did not
    /// vote for the proposal.
    ///
    /// To forward to all participants that did not vote for the proposal, see [ForwardingPolicy::SilentVoters].
    SilentLeader,
}

impl ForwardingPolicy {
    /// Returns true if the policy is enabled.
    pub const fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// The certified root from which a Simplex instance starts.
#[derive(Clone, Debug)]
pub enum Floor<S: Scheme, D: Digest> {
    /// Start from the epoch genesis payload at view 0.
    Genesis(D),
    /// Start from an already-finalized proposal.
    Finalized(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Floor<S, D> {
    fn assert<Rng>(&self, epoch: Epoch, rng: &mut Rng, scheme: &S, strategy: &impl Strategy)
    where
        Rng: CryptoRngCore,
        S: super::scheme::Scheme<D>,
    {
        if let Self::Finalized(finalization) = self {
            assert_eq!(
                finalization.epoch(),
                epoch,
                "floor finalization must be in the configured epoch"
            );
            assert!(
                !finalization.view().is_zero(),
                "use Floor::Genesis for the genesis view"
            );
            assert!(
                finalization.verify(rng, scheme, strategy),
                "floor finalization must verify"
            );
        }
    }
}

/// Configuration for the consensus engine.
pub struct Config<S, L, B, D, A, R, F, T>
where
    S: Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
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

    /// Strategy for parallel operations.
    pub strategy: T,

    /// Partition for the consensus engine.
    pub partition: String,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: NonZeroUsize,

    /// Epoch for the consensus engine. Each running engine should have a unique epoch.
    pub epoch: Epoch,

    /// Certified root for the consensus engine.
    pub floor: Floor<S, D>,

    /// Number of bytes to buffer when replaying during startup.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer to use for each blob in the journal.
    pub write_buffer: NonZeroUsize,

    /// Page cache for the journal.
    pub page_cache: CacheRef,

    /// Amount of time to wait for a leader to propose a payload
    /// in a view.
    pub leader_timeout: Duration,

    /// Amount of time to wait for certification progress in a view
    /// before attempting to skip the view.
    ///
    /// This timeout must be greater than the leader timeout.
    pub certification_timeout: Duration,

    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub timeout_retry: Duration,

    /// Number of views behind the finalized tip to track for recent activity.
    ///
    /// Durable safety evidence may be retained longer when stable-leader terms
    /// require it for same-term vote safety or skipped-view validation.
    pub activity_timeout: ViewDelta,

    /// Move to nullify immediately if the selected leader has been inactive
    /// for at least this long.
    ///
    /// This timeout must be greater than the certification timeout and timeout retry.
    pub skip_timeout: Duration,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Number of concurrent requests to make at once.
    pub fetch_concurrent: NonZeroUsize,

    /// Number of consecutive views in which a leader remains stable (a "term").
    ///
    /// When `term_length` is 1, every view has an independent leader (the default behavior).
    /// When `term_length` is greater than 1, views are grouped into terms and the same
    /// leader serves for each view in the term. If a nullification is formed in any view
    /// of a term, participants skip the rest of the term.
    pub term_length: TermLength,

    /// If true, stop voting to notarize later views in a term after voting to
    /// nullify any earlier view in that term.
    pub term_stop_notarize_on_nullify: bool,

    /// Maximum time an entered view may remain unfinalized before we allow a
    /// local nullify vote for the current view.
    ///
    /// With stable leaders, a Byzantine leader can keep every per-view timer
    /// satisfied while preventing finality: each view notarizes and certifies
    /// (so the leader and certification timeouts never fire), but no
    /// finalization certificate forms. With a `term_length` of 1, leader
    /// rotation bounds such a stall to a single view. With longer terms, this
    /// timeout bounds it instead: it tracks the oldest entered, unfinalized
    /// view in the current term and triggers a nullify vote for the current
    /// view when it expires, skipping the rest of the term.
    ///
    /// This timeout must be greater than the certification timeout so normal
    /// proposal and certification paths have a chance to complete before
    /// term-level abandonment.
    pub finalization_timeout: Duration,

    /// Policy for proactively forwarding certified blocks when entering the
    /// next view.
    pub forwarding: ForwardingPolicy,
}

impl<
        S: Scheme,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: CertifiableAutomaton<Context = Context<D, S::PublicKey>>,
        R: Relay,
        F: Reporter<Activity = Activity<S, D>>,
        T: Strategy,
    > Config<S, L, B, D, A, R, F, T>
{
    /// Assert enforces that all configuration values are valid.
    ///
    /// The RNG is used to verify finalized floor certificates.
    pub fn assert<Rng>(&self, rng: &mut Rng)
    where
        Rng: CryptoRngCore,
        S: super::scheme::Scheme<D>,
    {
        assert!(
            !self.scheme.participants().is_empty(),
            "there must be at least one participant"
        );

        // Vote-to-nullify timeouts.
        // finalization_timeout > certification_timeout > leader_timeout > 0.
        // skip_timeout > certification_timeout and timeout_retry.
        assert!(
            self.leader_timeout > Duration::default(),
            "leader timeout must be greater than zero"
        );
        assert!(
            self.certification_timeout > self.leader_timeout,
            "certification timeout must be greater than leader timeout"
        );
        assert!(
            self.finalization_timeout > self.certification_timeout,
            "finalization timeout must be greater than certification timeout"
        );

        assert!(
            self.skip_timeout > self.certification_timeout,
            "skip timeout must be greater than certification timeout"
        );
        assert!(
            self.skip_timeout > self.timeout_retry,
            "skip timeout must be greater than timeout retry"
        );
        assert!(
            self.timeout_retry > Duration::default(),
            "timeout retry broadcast must be greater than zero"
        );
        assert!(
            !self.activity_timeout.is_zero(),
            "activity timeout must be greater than zero"
        );
        assert!(
            self.fetch_timeout > Duration::default(),
            "fetch timeout must be greater than zero"
        );
        self.floor
            .assert(self.epoch, rng, &self.scheme, &self.strategy);
    }
}
