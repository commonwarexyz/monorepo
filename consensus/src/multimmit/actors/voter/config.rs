//! Voter configuration.

use crate::{
    Automaton, Relay, Reporter,
    multimmit::{
        actors::ingress::IngressLimits,
        config::Profile,
        scheme::bls12381::Scheme,
        storage::Recovered,
        types::{Activity, Context},
    },
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_storage::Context as StorageContext;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// Registers the counter of peers blocked for authenticated equivocation under `context`.
pub(crate) fn blocked_counter(context: &impl Metrics) -> Counter {
    context
        .child("voter")
        .counter("blocked", "peers blocked for authenticated equivocation")
}

/// Configuration for the voter.
pub(crate) struct Config<E, H, P, V, A, R, F, C, B>
where
    E: StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    /// Scheme holding this replica's key material (or verifier-only material).
    pub(crate) scheme: Scheme<P, V>,
    /// Execution strategy for view-critical CPU-heavy cryptography.
    ///
    /// Carries local signing and V-QC and L-QC assembly: the work between a quorum arriving and
    /// the artifact it authorizes leaving this replica.
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
    /// Observation cohorts the ingress actor may have in flight; sizes the observation queue so a
    /// credited cohort is never rejected.
    pub(crate) observation_capacity: NonZeroUsize,
}

/// Retry units in the timer ceiling.
const UNITS_PER_CEILING: u32 = 10;

/// Retry units in the longest publication retry backoff.
const RETRY_CEILING_UNITS: u32 = 2;

/// Retry units between two heartbeats.
const HEARTBEAT_UNITS: u32 = 5;

/// Returns the application-validation width available to each producer chain.
///
/// A chain's blocks above its accepted tip span at most its maximum tip lead, so wider validation
/// never helps.
pub(crate) fn validation_parallelism<D: Digest>(profile: &Profile<D>) -> usize {
    (profile.codec().window().max_tip_lead() as usize)
        .min(profile.resources().max_verification_batch())
}

/// Bounded execution and retry policy for the voter.
#[derive(Copy, Clone, Debug)]
pub(crate) struct VoterLimits {
    /// Initial publication retry backoff.
    pub(crate) retry_initial: Duration,
    /// Maximum publication retry backoff.
    pub(crate) retry_ceiling: Duration,
    /// Interval between Relay refreshes and periodic metrics.
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
    /// Derives the voter's policy from `profile`'s timer ceiling.
    ///
    /// The policy recovers from lost messages rather than tracking the network's delay, so it
    /// scales with the ceiling, the bound on how long any protocol wait lasts. With a unit of
    /// [`UNITS_PER_CEILING`]-th of the ceiling, publication retries start at an eighth of a unit
    /// and back off to [`RETRY_CEILING_UNITS`] units, and the heartbeat runs every
    /// [`HEARTBEAT_UNITS`] units. `checkpoint_interval` sets how many acknowledged journal events
    /// separate two checkpoint snapshots.
    pub(crate) fn from_profile<D: Digest>(
        profile: &Profile<D>,
        checkpoint_interval: NonZeroU64,
    ) -> Self {
        let unit =
            (profile.tuning().timer_ceiling / UNITS_PER_CEILING).max(Duration::from_nanos(1));
        Self {
            retry_initial: (unit / 8).max(Duration::from_nanos(1)),
            retry_ceiling: unit.saturating_mul(RETRY_CEILING_UNITS),
            heartbeat: unit.saturating_mul(HEARTBEAT_UNITS),
            checkpoint_interval,
            view_cohort_items: IngressLimits::VIEW_COHORT_ITEMS,
        }
    }
}
