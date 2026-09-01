//! Voter configuration.

use crate::{
    Automaton, Relay, Reporter,
    multimmit::{
        actors::ingress::IngressLimits,
        config::{Profile, RETRY_CEILING_VIEWS},
        scheme::bls12381_threshold::Scheme,
        storage::Recovered,
        types::{Activity, Context},
    },
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_storage::Context as StorageContext;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// Registers the counter of peers blocked for authenticated equivocation under `context`.
///
/// The counter is labelled with the batcher context so the dashboard metric name stays stable.
pub(crate) fn blocked_counter(context: &impl Metrics) -> Counter {
    context
        .child("batcher")
        .counter("blocked", "peers blocked for authenticated equivocation")
}

/// Configuration for the voter.
pub(crate) struct Config<E, H, P, V, A, R, F, T, C, B>
where
    E: Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    /// Scheme holding this replica's key material (or verifier-only material).
    pub(crate) scheme: Scheme<P, V>,
    /// Execution strategy for bulk CPU-heavy cryptography.
    ///
    /// Carries data-availability certificate recovery, the one class of assembly the round does
    /// not wait on.
    pub(crate) strategy: T,
    /// Execution strategy for view-critical CPU-heavy cryptography.
    ///
    /// Carries local signing and V-QC, L-QC, and nullification assembly: the work between a
    /// quorum arriving and the artifact it authorizes leaving this replica.
    pub(crate) critical_strategy: C,
    /// The attached application automaton.
    pub(crate) automaton: A,
    /// The application payload relay.
    pub(crate) relay: R,
    /// Best-effort sink for machine-authorized activity.
    pub(crate) reporter: F,
    /// Peer blocker for participants the machine proves equivocated.
    pub(crate) blocker: B,
    /// Peers blocked for authenticated equivocation, registered by [`blocked_counter`].
    pub(crate) blocked: Counter,
    /// The machine and stores to drive, fresh or recovered.
    pub(crate) recovered: Recovered<E, H, V>,
    /// Bounded execution and retry policy.
    pub(crate) limits: VoterLimits,
    /// Capacity of each inbound queue.
    pub(crate) mailbox_size: NonZeroUsize,
}

/// View timeouts between two heartbeats.
const HEARTBEAT_VIEWS: u32 = 5;

/// Returns the application-validation width available to each producer chain.
pub(crate) fn validation_parallelism<D: Digest>(profile: &Profile<D>) -> usize {
    profile
        .codec()
        .pipeline_depth()
        .min(profile.resources().max_verification_batch())
}

/// Returns the global application-validation capacity across all producer chains.
pub(crate) fn validation_capacity<D: Digest>(profile: &Profile<D>) -> usize {
    profile
        .codec()
        .chains()
        .saturating_mul(validation_parallelism(profile))
        .min(profile.resources().max_cached_artifacts())
}

/// Bounded execution and retry policy for the voter.
#[derive(Copy, Clone, Debug)]
pub(crate) struct VoterLimits {
    /// Initial publication retry backoff.
    pub(crate) retry_initial: Duration,
    /// Maximum publication retry backoff.
    pub(crate) retry_ceiling: Duration,
    /// Recent peer activity window for early leader timeouts; `None` disables the policy.
    /// Must exceed the publication retry ceiling.
    pub(crate) skip_timeout: Option<Duration>,
    /// Interval between Relay refreshes, periodic metrics, and producer-stall checks.
    pub(crate) heartbeat: Duration,
    /// Acknowledged journal events between checkpoint snapshots.
    pub(crate) checkpoint_interval: NonZeroU64,
    /// Maximum artifacts merged into one view-critical observation batch.
    ///
    /// Matches the ingress actor's view-critical cohort bound, so merging queued cohorts never
    /// enlarges the batch a vote or certificate verdict waits behind.
    pub(crate) view_cohort_items: NonZeroUsize,
}

impl VoterLimits {
    /// Derives the voter's policy from `profile`'s view timeout and early-timeout window.
    ///
    /// Publication retries start at an eighth of the view timeout and back off to
    /// [`RETRY_CEILING_VIEWS`] view timeouts; the heartbeat runs every [`HEARTBEAT_VIEWS`] view
    /// timeouts. `checkpoint_interval` sets how many acknowledged journal events separate two
    /// checkpoint snapshots.
    pub(crate) fn from_profile<D: Digest>(
        profile: &Profile<D>,
        checkpoint_interval: NonZeroU64,
    ) -> Self {
        let tuning = profile.tuning();
        let view_timeout = tuning.view_timeout;
        Self {
            retry_initial: (view_timeout / 8).max(Duration::from_nanos(1)),
            retry_ceiling: view_timeout.saturating_mul(RETRY_CEILING_VIEWS),
            skip_timeout: tuning.skip_timeout,
            heartbeat: view_timeout.saturating_mul(HEARTBEAT_VIEWS),
            checkpoint_interval,
            view_cohort_items: IngressLimits::VIEW_COHORT_ITEMS,
        }
    }
}
