//! Operator tuning and the local profile an engine derives from it.

use super::{Error, Protocol};
use crate::{
    multimmit::{machine::max_lane_artifacts, types::CodecConfig},
    types::{Participant, View, ViewDelta},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{Faults as _, N5f1};
use core::{num::NonZeroUsize, time::Duration};

/// Cache slots held back for one self-certifying view proof, which no other work may consume.
const VIEW_PROOF_SLOTS: usize = 1;

/// Cache slots held back for this node's atomic timeout choice: its no-vote and nullify pair.
const TIMEOUT_CHOICE_SLOTS: usize = 2;

/// Cache slots the live view needs beyond its `n - f` messages: the parent V-QC, the leader
/// block, and the certificate those messages assemble.
const LIVE_VIEW_SLOTS: usize = 3;

/// Exit-certificate classes forwarded per view: one V-QC and one nullification.
const EXIT_CERTIFICATE_CLASSES: usize = 2;

/// Cache slots budgeted per participant in each retained view: a producer block, its DA
/// certificate, and up to two view messages (a vote or no-vote, and a nullify).
const VIEW_SLOTS_PER_PARTICIPANT: u64 = 4;

/// Cache slots budgeted per retained view regardless of committee size: the leader block and the
/// V-QC, nullification, and L-QC that may close the view.
const VIEW_SLOTS_PER_VIEW: u64 = 4;

/// Live cache slots per participant for uncertified future traffic, in-flight verification, and
/// publications ordering has not yet retired.
const LIVE_SLOTS_PER_PARTICIPANT: u64 = 48;

/// Retained future-view artifacts per participant.
const FUTURE_ARTIFACTS_PER_PARTICIPANT: u64 = 8;

/// Artifacts per participant in one verification request.
const VERIFICATION_BATCH_PER_PARTICIPANT: u64 = 8;

/// Outstanding verification jobs per participant.
const INFLIGHT_VERIFICATIONS_PER_PARTICIPANT: u64 = 8;

/// Untrusted dependency waiters per participant.
const DEPENDENCY_WAITERS_PER_PARTICIPANT: u64 = 4;

/// Retained views per view of future-traffic horizon: uncertified traffic is admitted up to an
/// eighth of the retention window ahead of the durable view.
const RETAINED_VIEWS_PER_FUTURE_VIEW: u64 = 8;

/// Smallest future-traffic horizon, in views: it covers the atomic timeout choice and one
/// self-certifying proof when the retention window is shorter than eight views.
const MIN_FUTURE_VIEW_DISTANCE: u64 = 3;

/// Pipeline depths a producer block or data-availability vote may sit above its chain's certified
/// frontier.
///
/// A producer builds height `h` once it holds the certificate for `h - pipeline_depth`, so its
/// blocks lead its own frontier by at most one pipeline depth. The second depth covers this node's
/// frontier trailing the producer's: the certificates behind the lead travel on the certificate
/// plane and verify apart from the blocks, and while production is bound by the pipeline a DA
/// round certifies one depth of heights. Traffic beyond the window is dropped without blame: its
/// publication repeats until the producer certifies it, and a node can vote on it only once its own
/// frontier is within one depth (see the chain plane's eligibility).
pub(crate) const HEIGHT_WINDOW_PIPELINES: u64 = 2;

/// Verified producer blocks retained at one chain position: a producer's block and one conflicting
/// block, which proves the producer equivocated.
///
/// Every chain's full window of them, `chains * 2 * 2d` slots for pipeline depth `d`, fits the
/// derived remote cache partition while `d` is at most the view retention plus 13: that partition
/// holds [`LIVE_SLOTS_PER_PARTICIPANT`] slots per participant and [`VIEW_SLOTS_PER_PARTICIPANT`]
/// per participant in each retained view, and there are no more chains than participants. A deeper
/// pipeline needs a longer retention for the same guarantee.
pub(crate) const VERIFIED_BLOCKS_PER_HEIGHT: usize = 2;

/// View timeouts in the default recent-activity window for early leader timeouts.
const SKIP_TIMEOUT_VIEWS: u32 = 5;

/// View timeouts in the longest publication retry backoff.
pub(crate) const RETRY_CEILING_VIEWS: u32 = 2;

/// Returns the live work a committee of `participants` bounds: uncertified future traffic,
/// in-flight verification, and publications ordering has not yet retired.
///
/// The liveness partition holds the atomic timeout choice and one self-certifying proof.
fn live_work(participants: usize) -> u64 {
    let committee = participants.max(1) as u64;
    let quorum = N5f1::quorum(participants).max(1) as u64;
    quorum
        .saturating_add(committee.saturating_mul(LIVE_SLOTS_PER_PARTICIPANT))
        .saturating_add((TIMEOUT_CHOICE_SLOTS + VIEW_PROOF_SLOTS) as u64)
}

/// Returns the most durable external actions, publications among them, an engine keeps awaiting
/// acknowledgement for a committee of `participants`.
///
/// A relay that serves those publications back to the engine keeps at least this many of its own
/// blocks.
pub(crate) fn max_outbox_effects(participants: usize) -> NonZeroUsize {
    NonZeroUsize::new(usize::try_from(live_work(participants)).unwrap_or(usize::MAX))
        .expect("live work is non-zero")
}

/// The smallest artifact byte limit an unset limit resolves to.
///
/// The artifact byte limit sizes the core's input lanes, the voter's validation bytes, and the
/// snapshot and journal decode caps, so this floor keeps those budgets at least this large when a
/// small committee's codec bound is tiny.
const MIN_ARTIFACT_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();

/// Returns the artifact byte limit `configured` sets under `codec`, or the larger of the codec
/// bound and [`MIN_ARTIFACT_BYTES`] when it is unset.
fn artifact_byte_limit<V: Variant, D: Digest>(
    codec: CodecConfig,
    configured: Option<NonZeroUsize>,
) -> Result<NonZeroUsize, Error> {
    let required = codec
        .max_artifact_bytes::<V, D>()
        .ok_or(Error::EncodedSizeOverflow)?;
    match configured {
        Some(limit) if limit < required => Err(Error::ArtifactByteLimitTooSmall {
            required: required.get(),
            actual: limit.get(),
        }),
        Some(limit) => Ok(limit),
        None => Ok(required.max(MIN_ARTIFACT_BYTES)),
    }
}

/// Whether this machine may authorize validator actions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// A validator acting for one ordered committee participant.
    Validator(Participant),
    /// A verifier-only replica that never authorizes signatures.
    Observer,
}

/// The knobs an operator chooses for one deployment.
///
/// Every internal bound (artifact cache, forwarding history) is derived from these plus the
/// committee size, so a manifest that cannot sustain operation is unrepresentable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// How long a view may run before this node votes to nullify it.
    ///
    /// This must be non-zero and cover the `2 * delta` synchrony deadline plus the deployment's
    /// bounded ingress, scheduling, and verification latency.
    pub view_timeout: Duration,
    /// How long to wait before retrying a producer that declined to build. Must be non-zero.
    pub production_interval: Duration,
    /// How many views below the current view stay retained.
    ///
    /// The machine can never act in a view it has already left, so this window bounds memory even
    /// when finality stalls. It also fixes how far behind a peer may be and still be served
    /// directly from retained state.
    pub view_retention: ViewDelta,
    /// The largest canonical protocol artifact this deployment accepts.
    ///
    /// `None` takes the largest artifact the epoch's codec bounds admit, and at least 1 MiB. A
    /// limit below that codec bound is rejected, as is one whose derived byte budgets do not fit
    /// this target.
    pub max_artifact_bytes: Option<NonZeroUsize>,
    /// The recent-activity window for early timeouts of remote leaders.
    ///
    /// At view entry, an inactive leader may be timed out early when a view quorum, counting this
    /// validator, was active within the window. The window must exceed twice the view timeout,
    /// the publication retry ceiling, and should cover the deployment's message and scheduling
    /// delays. `None` takes five view timeouts, and disables early timeouts only when that
    /// overflows.
    pub skip_timeout: Option<Duration>,
}

impl Tuning {
    /// Returns the default tuning for `view_timeout`, with every derived limit left unset.
    pub const fn new(view_timeout: Duration) -> Self {
        Self {
            view_timeout,
            production_interval: Duration::from_millis(250),
            view_retention: ViewDelta::new(64),
            max_artifact_bytes: None,
            skip_timeout: None,
        }
    }

    /// Checks this tuning against `protocol` as the engine does when it opens.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuning is invalid or cannot sustain the epoch's committee.
    pub fn validate<H: Hasher, V: Variant>(
        &self,
        protocol: &Protocol<H::Digest>,
    ) -> Result<(), Error> {
        Profile::<H::Digest>::new::<V>(protocol.clone(), Role::Observer, *self).map(|_| ())
    }

    /// Resolves the limits this tuning leaves unset against `codec` and checks the artifact byte
    /// limit it sets.
    ///
    /// # Errors
    ///
    /// Returns an error when the epoch's encoded maxima do not fit this target, or when the
    /// artifact byte limit cannot admit every bounded protocol artifact.
    fn resolve<V: Variant, D: Digest>(self, codec: CodecConfig) -> Result<ResolvedTuning, Error> {
        let max_artifact_bytes = artifact_byte_limit::<V, D>(codec, self.max_artifact_bytes)?;
        Ok(ResolvedTuning::new(self, max_artifact_bytes))
    }
}

impl Default for Tuning {
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

/// A [`Tuning`] with every limit it leaves unset resolved against the epoch's codec bounds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTuning {
    /// How long a view may run before this node votes to nullify it.
    pub(crate) view_timeout: Duration,
    /// How long to wait before retrying a producer that declined to build.
    pub(crate) production_interval: Duration,
    /// How many views below the current view stay retained.
    pub(crate) view_retention: ViewDelta,
    /// The largest canonical protocol artifact this deployment accepts.
    pub(crate) max_artifact_bytes: NonZeroUsize,
    /// The recent-activity window for early timeouts of remote leaders, or `None` when the
    /// default window overflows.
    pub(crate) skip_timeout: Option<Duration>,
}

impl ResolvedTuning {
    /// Resolves `tuning`'s early-timeout window, with `max_artifact_bytes` the resolved artifact
    /// byte limit.
    fn new(tuning: Tuning, max_artifact_bytes: NonZeroUsize) -> Self {
        Self {
            view_timeout: tuning.view_timeout,
            production_interval: tuning.production_interval,
            view_retention: tuning.view_retention,
            max_artifact_bytes,
            skip_timeout: tuning
                .skip_timeout
                .or_else(|| tuning.view_timeout.checked_mul(SKIP_TIMEOUT_VIEWS)),
        }
    }
}

/// Limits for adversarially controlled local work and reserved protocol capacity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    max_artifact_bytes: NonZeroUsize,
    max_cached_artifacts: NonZeroUsize,
    max_finality_pools: NonZeroUsize,
    max_verification_batch: NonZeroUsize,
    max_inflight_verifications: NonZeroUsize,
    max_future_view_distance: u64,
    max_future_artifacts: NonZeroUsize,
    max_dependency_waiters: NonZeroUsize,
    max_outbox_effects: NonZeroUsize,
    max_forwarded_certificates: NonZeroUsize,
}

impl ResourceLimits {
    /// Creates explicit bounds for ingress, verification, and dependency retention.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        max_artifact_bytes: NonZeroUsize,
        max_cached_artifacts: NonZeroUsize,
        max_verification_batch: NonZeroUsize,
        max_inflight_verifications: NonZeroUsize,
        max_future_view_distance: u64,
        max_future_artifacts: NonZeroUsize,
        max_dependency_waiters: NonZeroUsize,
        max_outbox_effects: NonZeroUsize,
        max_forwarded_certificates: NonZeroUsize,
    ) -> Self {
        Self {
            max_artifact_bytes,
            max_cached_artifacts,
            max_finality_pools: max_cached_artifacts,
            max_verification_batch,
            max_inflight_verifications,
            max_future_view_distance,
            max_future_artifacts,
            max_dependency_waiters,
            max_outbox_effects,
            max_forwarded_certificates,
        }
    }
    /// Returns the largest encoded artifact accepted for verification.
    pub const fn max_artifact_bytes(self) -> usize {
        self.max_artifact_bytes.get()
    }

    /// Sets the largest encoded artifact accepted for verification.
    #[cfg(test)]
    pub(crate) const fn with_max_artifact_bytes(
        mut self,
        max_artifact_bytes: NonZeroUsize,
    ) -> Self {
        self.max_artifact_bytes = max_artifact_bytes;
        self
    }

    /// Sets the retained artifact-record ceiling and, as [`Self::new`] does, the finality-pool
    /// budget.
    #[cfg(test)]
    pub(crate) const fn with_max_cached_artifacts(
        mut self,
        max_cached_artifacts: NonZeroUsize,
    ) -> Self {
        self.max_cached_artifacts = max_cached_artifacts;
        self.max_finality_pools = max_cached_artifacts;
        self
    }

    /// Returns the maximum number of retained artifact records.
    pub const fn max_cached_artifacts(self) -> usize {
        self.max_cached_artifacts.get()
    }

    /// Returns the cache partition available to untrusted non-proof ingress.
    pub(crate) const fn remote_artifact_capacity(self) -> usize {
        self.max_cached_artifacts()
            .saturating_sub(TIMEOUT_CHOICE_SLOTS + VIEW_PROOF_SLOTS)
    }

    /// Returns the cache partition available to locally authorized non-proof work.
    pub(crate) const fn local_artifact_capacity(self) -> usize {
        self.max_cached_artifacts().saturating_sub(VIEW_PROOF_SLOTS)
    }

    /// Returns the pool budget for unfinalized leaders and the normal certified-view window.
    ///
    /// Quorum-authenticated pools may exceed this budget while ordering is stalled. They remain
    /// retained within the view retention window.
    pub const fn max_finality_pools(self) -> usize {
        self.max_finality_pools.get()
    }

    /// Sets a distinct finality-pool budget.
    #[cfg(test)]
    pub(crate) const fn with_max_finality_pools(
        mut self,
        max_finality_pools: NonZeroUsize,
    ) -> Self {
        self.max_finality_pools = max_finality_pools;
        self
    }

    /// Returns the maximum number of artifacts in one verification request.
    pub const fn max_verification_batch(self) -> usize {
        self.max_verification_batch.get()
    }

    /// Returns the maximum number of outstanding verification jobs.
    pub const fn max_inflight_verifications(self) -> usize {
        self.max_inflight_verifications.get()
    }

    /// Sets the maximum number of outstanding verification jobs.
    #[cfg(test)]
    pub(crate) const fn with_max_inflight_verifications(
        mut self,
        max_inflight_verifications: NonZeroUsize,
    ) -> Self {
        self.max_inflight_verifications = max_inflight_verifications;
        self
    }

    /// Returns the largest distance accepted for uncertified future-view traffic.
    pub const fn max_future_view_distance(self) -> u64 {
        self.max_future_view_distance
    }

    /// Sets the largest distance accepted for uncertified future-view traffic.
    #[cfg(test)]
    pub(crate) const fn with_max_future_view_distance(
        mut self,
        max_future_view_distance: u64,
    ) -> Self {
        self.max_future_view_distance = max_future_view_distance;
        self
    }

    /// Returns the maximum number of retained future-view artifacts.
    pub const fn max_future_artifacts(self) -> usize {
        self.max_future_artifacts.get()
    }

    /// Sets the maximum number of retained future-view artifacts.
    #[cfg(test)]
    pub(crate) const fn with_max_future_artifacts(
        mut self,
        max_future_artifacts: NonZeroUsize,
    ) -> Self {
        self.max_future_artifacts = max_future_artifacts;
        self
    }

    /// Returns the ceiling for untrusted waiters and remembered dependency failures.
    pub const fn max_dependency_waiters(self) -> usize {
        self.max_dependency_waiters.get()
    }

    /// Sets the ceiling for untrusted waiters and remembered dependency failures.
    #[cfg(test)]
    pub(crate) const fn with_max_dependency_waiters(
        mut self,
        max_dependency_waiters: NonZeroUsize,
    ) -> Self {
        self.max_dependency_waiters = max_dependency_waiters;
        self
    }

    /// Returns the maximum number of durable external actions awaiting acknowledgement.
    pub const fn max_outbox_effects(self) -> usize {
        self.max_outbox_effects.get()
    }

    /// Sets the maximum number of durable external actions awaiting acknowledgement.
    #[cfg(test)]
    pub(crate) const fn with_max_outbox_effects(
        mut self,
        max_outbox_effects: NonZeroUsize,
    ) -> Self {
        self.max_outbox_effects = max_outbox_effects;
        self
    }

    /// Returns the number of per-view certificate forwarding facts retained at once.
    pub const fn max_forwarded_certificates(self) -> usize {
        self.max_forwarded_certificates.get()
    }

    /// Sets the ceiling for V-QC and nullification forwarding facts.
    ///
    /// A retained view can hold one first-forwarding fact of each certificate class.
    #[cfg(test)]
    pub(crate) const fn with_max_forwarded_certificates(
        mut self,
        max_forwarded_certificates: NonZeroUsize,
    ) -> Self {
        self.max_forwarded_certificates = max_forwarded_certificates;
        self
    }
}

/// The validated local profile of one machine instance: the epoch's [`Protocol`], this node's
/// [`Role`], the operator's [`Tuning`], and the [`ResourceLimits`] derived from them.
#[derive(Clone, Debug)]
pub struct Profile<D: Digest> {
    protocol: Protocol<D>,
    role: Role,
    tuning: ResolvedTuning,
    resources: ResourceLimits,
}

impl<D: Digest> Profile<D> {
    /// Checks the bounds a profile must satisfy, whether derived or supplied by a test.
    fn validate(
        protocol: &Protocol<D>,
        role: Role,
        tuning: ResolvedTuning,
        resources: ResourceLimits,
    ) -> Result<(), Error> {
        let participants = protocol.codec_config().participants();
        if let Role::Validator(participant) = role
            && participant.get() as usize >= participants
        {
            return Err(Error::ValidatorOutOfRange(participant));
        }

        if tuning.view_timeout.is_zero() {
            return Err(Error::ZeroViewTimeout);
        }
        if tuning.production_interval.is_zero() {
            return Err(Error::ZeroProductionInterval);
        }
        if tuning.view_retention.get() == 0 {
            return Err(Error::ZeroViewRetention);
        }
        // Exceeding the retry ceiling also exceeds the view timeout.
        let retry_ceiling = tuning.view_timeout.saturating_mul(RETRY_CEILING_VIEWS);
        if let Some(skip_timeout) = tuning.skip_timeout
            && skip_timeout <= retry_ceiling
        {
            return Err(Error::SkipTimeoutTooShort {
                retry_ceiling,
                actual: skip_timeout,
            });
        }

        // Every core lane's byte bound is a multiple of the artifact byte limit, and the largest
        // must fit.
        let max_artifact_bytes =
            max_lane_artifacts(&resources).map_or(0, |per_artifact| usize::MAX / per_artifact);
        if resources.max_artifact_bytes() > max_artifact_bytes {
            return Err(Error::ArtifactByteLimitTooLarge {
                max: max_artifact_bytes,
                actual: resources.max_artifact_bytes(),
            });
        }

        // Every view below the live one that is still retained needs at least its exit proof.
        let required = N5f1::quorum(participants) as usize + LIVE_VIEW_SLOTS;
        let actual = resources.max_cached_artifacts();
        if actual < required {
            return Err(Error::ArtifactCacheTooSmall { required, actual });
        }
        let retention = Error::RetentionExceedsArtifactCache {
            view_retention: tuning.view_retention.get(),
            actual,
        };
        let retained = Self::retained_views(tuning.view_retention).ok_or(retention.clone())?;
        let required = required.checked_add(retained - 1).ok_or(retention)?;
        if actual < required {
            return Err(Error::ArtifactCacheTooSmall { required, actual });
        }
        let forwarded = retained
            .checked_mul(EXIT_CERTIFICATE_CLASSES)
            .ok_or(Error::Overflow)?;
        if resources.max_forwarded_certificates() < forwarded {
            return Err(Error::ForwardingHistoryTooSmall {
                required: forwarded,
                actual: resources.max_forwarded_certificates(),
            });
        }

        // One pinned slot covers each locally retained or admissible future view. The remaining
        // protected partition holds one liveness primary for each of f faulty owners plus one
        // correct owner.
        let pinned = Self::required_pinned_finality_pools(tuning.view_retention, resources)
            .ok_or(Error::Overflow)?;
        let required = pinned
            .checked_add((N5f1::max_faults(participants) + 1) as usize)
            .ok_or(Error::Overflow)?;
        if resources.max_finality_pools() < required {
            return Err(Error::FinalityPoolCapacityTooSmall {
                required,
                actual: resources.max_finality_pools(),
            });
        }

        Ok(())
    }

    /// Returns the number of views the machine may hold at once: the current one and the window
    /// below it.
    fn retained_views(view_retention: ViewDelta) -> Option<usize> {
        usize::try_from(view_retention.get().checked_add(1)?).ok()
    }

    fn required_pinned_finality_pools(
        view_retention: ViewDelta,
        resources: ResourceLimits,
    ) -> Option<usize> {
        Self::retained_views(view_retention)?
            .checked_add(usize::try_from(resources.max_future_view_distance()).ok()?)
    }

    /// Creates a profile with explicit internal bounds.
    ///
    /// Production code derives these from [`Tuning`] so an unsustainable manifest cannot be
    /// expressed. Tests use this to drive the overflow paths those derived bounds are sized to
    /// avoid.
    #[cfg(test)]
    pub(crate) fn with_limits(
        protocol: Protocol<D>,
        role: Role,
        tuning: Tuning,
        resources: ResourceLimits,
    ) -> Result<Self, Error> {
        let tuning = ResolvedTuning::new(tuning, resources.max_artifact_bytes);
        Self::validate(&protocol, role, tuning, resources)?;
        Ok(Self {
            protocol,
            role,
            tuning,
            resources,
        })
    }

    /// Derives every internal bound from the committee size and the operator's resolved tuning.
    ///
    /// The relationships here are the ones the validation below enforces: the artifact cache must
    /// cover live work plus a slot per retained view, and the forwarding history must cover one
    /// V-QC and one nullification per retained view. Deriving them together is what makes an
    /// unsustainable manifest impossible to express. The derived values are wider than those
    /// minima because a retained view holds a whole view's working set, not a single artifact.
    fn derive(participants: usize, tuning: ResolvedTuning) -> ResourceLimits {
        let retained = tuning.view_retention.get().saturating_add(1);
        let committee = participants.max(1) as u64;

        let nonzero_usize = |value: u64| {
            NonZeroUsize::new(usize::try_from(value.max(1)).unwrap_or(usize::MAX))
                .expect("value is non-zero")
        };

        let per_view = committee
            .saturating_mul(VIEW_SLOTS_PER_PARTICIPANT)
            .saturating_add(VIEW_SLOTS_PER_VIEW);
        let live = live_work(participants);
        let future = committee.saturating_mul(FUTURE_ARTIFACTS_PER_PARTICIPANT);
        // How far above the durable view uncertified traffic is admitted. A node that retains
        // `retained` views behind itself serves peers that far back, so a proportionate horizon
        // ahead lets a node that promises more history also accept more of the gossip it needs
        // to close the gap. Widening this admits no more memory, because the future-view index
        // and the artifact cache bound that separately.
        let future_distance =
            (retained / RETAINED_VIEWS_PER_FUTURE_VIEW).max(MIN_FUTURE_VIEW_DISTANCE);
        ResourceLimits::new(
            tuning.max_artifact_bytes,
            nonzero_usize(live.saturating_add(per_view.saturating_mul(retained))),
            nonzero_usize(committee.saturating_mul(VERIFICATION_BATCH_PER_PARTICIPANT)),
            nonzero_usize(committee.saturating_mul(INFLIGHT_VERIFICATIONS_PER_PARTICIPANT)),
            future_distance,
            nonzero_usize(future),
            nonzero_usize(committee.saturating_mul(DEPENDENCY_WAITERS_PER_PARTICIPANT)),
            nonzero_usize(live),
            // A certificate for a view above the current one is forwarded before that view is
            // reached, so the bounded future-view index needs its own room here.
            nonzero_usize(
                retained
                    .saturating_add(future)
                    .saturating_mul(EXIT_CERTIFICATE_CLASSES as u64),
            ),
        )
    }

    /// Resolves `tuning` against `protocol`'s codec bounds, validates it, and derives this node's
    /// profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuning is invalid or when a validator role names a non-member.
    pub fn new<V: Variant>(
        protocol: Protocol<D>,
        role: Role,
        tuning: Tuning,
    ) -> Result<Self, Error> {
        let tuning = tuning.resolve::<V, D>(protocol.codec_config())?;
        let resources = Self::derive(protocol.codec_config().participants(), tuning);
        Self::validate(&protocol, role, tuning, resources)?;
        Ok(Self {
            protocol,
            role,
            tuning,
            resources,
        })
    }

    /// Returns the validated protocol configuration.
    pub const fn protocol(&self) -> &Protocol<D> {
        &self.protocol
    }

    /// Returns the epoch's bounded decode configuration.
    pub const fn codec(&self) -> CodecConfig {
        self.protocol.codec_config()
    }

    /// Returns the local node role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the operator's tuning with its derived limits resolved.
    pub const fn tuning(&self) -> ResolvedTuning {
        self.tuning
    }

    /// Returns how many views below the current view stay retained.
    pub const fn view_retention(&self) -> ViewDelta {
        self.tuning.view_retention
    }

    /// Returns the greatest view a node stops retaining once `view` is current.
    pub(crate) const fn retention_floor(&self, view: View) -> View {
        view.saturating_sub(self.tuning.view_retention)
            .saturating_sub(ViewDelta::new(1))
    }

    /// Returns how far above its chain's certified frontier a producer block or data-availability
    /// vote is admitted.
    pub(crate) const fn height_window(&self) -> u64 {
        (self.protocol.codec_config().pipeline_depth() as u64)
            .saturating_mul(HEIGHT_WINDOW_PIPELINES)
    }

    /// Returns the hard local resource ceilings.
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    pub(crate) fn pinned_finality_pools(&self) -> usize {
        Self::required_pinned_finality_pools(self.tuning.view_retention, self.resources)
            .expect("validated finality retention fits usize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{BlockRef, CertificateId, ChainId, EpochGenesis, PathLimits},
        types::{Epoch, Height},
    };
    use commonware_cryptography::{
        Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256::Digest as Sha256Digest,
    };

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PROFILE_TEST";

    fn protocol(participants: u32) -> Protocol<Sha256Digest> {
        protocol_with_limits(participants, PathLimits::new(1, 0).unwrap())
    }

    fn protocol_with_limits(participants: u32, limits: PathLimits) -> Protocol<Sha256Digest> {
        let epoch = Epoch::new(7);
        let tips = (0..participants)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    Sha256::hash(&[&chain.to_be_bytes()]),
                )
            })
            .collect();
        let genesis = EpochGenesis::new(
            epoch,
            Sha256::hash(&[b"leader genesis"]),
            CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
            CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
            tips,
        )
        .unwrap();

        Protocol::new(
            NAMESPACE,
            participants as usize,
            (0..participants).map(Participant::new).collect(),
            limits,
            genesis,
        )
        .unwrap()
    }

    fn tuning(view_retention: u64) -> Tuning {
        Tuning {
            view_retention: ViewDelta::new(view_retention),
            ..Tuning::default()
        }
    }

    fn profile(participants: u32, view_retention: u64) -> Result<Profile<Sha256Digest>, Error> {
        Profile::new::<MinPk>(
            protocol(participants),
            Role::Observer,
            tuning(view_retention),
        )
    }

    fn assert_artifact_byte_limit<V: Variant>() {
        let protocol = protocol_with_limits(11, PathLimits::new(3, 2).unwrap());
        let required = protocol
            .codec_config()
            .max_artifact_bytes::<V, Sha256Digest>()
            .unwrap();
        let resolved = |limit| {
            Profile::new::<V>(
                protocol.clone(),
                Role::Observer,
                Tuning {
                    max_artifact_bytes: limit,
                    ..tuning(64)
                },
            )
            .map(|profile| profile.resources().max_artifact_bytes())
        };
        assert_eq!(resolved(Some(required)), Ok(required.get()));
        let actual = NonZeroUsize::new(required.get() - 1).unwrap();
        let error = Error::ArtifactByteLimitTooSmall {
            required: required.get(),
            actual: actual.get(),
        };
        assert_eq!(resolved(Some(actual)), Err(error.clone()));
        let tuning = Tuning {
            max_artifact_bytes: Some(actual),
            ..tuning(64)
        };
        assert_eq!(tuning.validate::<Sha256, V>(&protocol), Err(error));
    }

    #[test]
    fn every_committee_and_retention_window_yields_a_valid_profile() {
        // Internal bounds are derived, so an operator cannot express a manifest the machine rejects.
        // If that ever stops holding, this fails for the shape that broke it.
        for participants in [1u32, 2, 5, 6, 7, 11, 16, 32, 64] {
            for view_retention in [1u64, 2, 64, 1_000, 50_000, 1_000_000] {
                let profile = profile(participants, view_retention);
                assert!(
                    profile.is_ok(),
                    "derived profile rejected for participants={participants} \
                     retention={view_retention}: {:?}",
                    profile.err()
                );
            }
        }
    }

    #[test]
    fn derived_caches_hold_every_chain_window_in_the_assumed_depth_range() {
        for participants in [1u32, 6, 16, 50, 64] {
            for view_retention in [1u64, 64, 1_000] {
                let deepest = view_retention + 13;
                for pipeline_depth in [1, 2, 32, 48, deepest].map(|depth| depth.min(deepest)) {
                    let limits =
                        PathLimits::new(u32::try_from(pipeline_depth).unwrap(), 0).unwrap();
                    // Deep pipelines carry large leader blocks.
                    let profile = Profile::new::<MinPk>(
                        protocol_with_limits(participants, limits),
                        Role::Observer,
                        Tuning {
                            max_artifact_bytes: NonZeroUsize::new(64 << 20),
                            ..tuning(view_retention)
                        },
                    )
                    .unwrap();
                    let windows = participants as usize
                        * VERIFIED_BLOCKS_PER_HEIGHT
                        * profile.height_window() as usize;
                    assert!(
                        profile.resources().remote_artifact_capacity() >= windows,
                        "chain windows exceed the remote partition for participants=\
                         {participants} depth={pipeline_depth} retention={view_retention}"
                    );
                }
            }
        }
    }

    #[test]
    fn zero_retention_is_rejected() {
        assert_eq!(profile(6, 0).unwrap_err(), Error::ZeroViewRetention);
    }

    #[test]
    fn production_profiles_enforce_the_exact_artifact_byte_bound_for_both_variants() {
        assert_artifact_byte_limit::<MinPk>();
        assert_artifact_byte_limit::<MinSig>();
    }

    #[test]
    fn explicit_test_limits_allow_an_undersized_artifact_byte_bound() {
        let protocol = protocol(6);
        let tuning = tuning(64);
        let derived = Profile::new::<MinPk>(protocol.clone(), Role::Observer, tuning)
            .unwrap()
            .resources();
        let resources = ResourceLimits {
            max_artifact_bytes: NonZeroUsize::new(1).unwrap(),
            ..derived
        };

        let profile = Profile::with_limits(protocol, Role::Observer, tuning, resources).unwrap();
        assert_eq!(profile.resources().max_artifact_bytes(), 1);
    }

    #[test]
    fn explicit_test_limits_cover_pinned_and_live_finality_partitions() {
        let protocol = protocol(6);
        let tuning = tuning(2);
        let derived = Profile::new::<MinPk>(protocol.clone(), Role::Observer, tuning)
            .unwrap()
            .resources();
        let pinned = 3 + derived.max_future_view_distance() as usize;
        let required = pinned + 2;
        let resources = derived.with_max_finality_pools(NonZeroUsize::new(required - 1).unwrap());

        assert_eq!(
            Profile::with_limits(protocol, Role::Observer, tuning, resources).unwrap_err(),
            Error::FinalityPoolCapacityTooSmall {
                required,
                actual: required - 1,
            }
        );
    }

    #[test]
    fn unrepresentable_required_capacities_are_overflow_errors() {
        let protocol = protocol(6);
        let derived = Profile::new::<MinPk>(protocol.clone(), Role::Observer, tuning(64))
            .unwrap()
            .resources();

        // Two forwarded exit certificates per retained view overflow usize.
        let resources = ResourceLimits {
            max_cached_artifacts: NonZeroUsize::new(usize::MAX).unwrap(),
            ..derived
        };
        assert_eq!(
            Profile::with_limits(
                protocol.clone(),
                Role::Observer,
                tuning((usize::MAX / 2) as u64),
                resources,
            )
            .unwrap_err(),
            Error::Overflow
        );

        // Pinned finality pools for the retained and future views overflow usize.
        let resources = ResourceLimits {
            max_future_view_distance: u64::MAX,
            ..derived
        };
        assert_eq!(
            Profile::with_limits(protocol, Role::Observer, tuning(64), resources).unwrap_err(),
            Error::Overflow
        );
    }

    #[test]
    fn derived_bounds_cover_the_retention_window() {
        // The three relationships the machine depends on: one cache slot per retained view on top of
        // a quorum of live work, one forwarded V-QC plus one forwarded nullification per retained
        // view, and a forward horizon for uncertified traffic proportionate to the window kept behind.
        for participants in [1u32, 6, 11, 32] {
            for view_retention in [1u64, 64, 10_000] {
                let profile =
                    profile(participants, view_retention).expect("derived profile is valid");
                let resources = profile.resources();
                let quorum = N5f1::quorum(participants as usize) as usize;
                let retained = view_retention as usize + 1;
                assert!(
                    resources.max_cached_artifacts() >= quorum + 3 + retained,
                    "cache does not cover live work plus the retention window \
                     (participants={participants}, retention={view_retention})"
                );
                assert!(
                    resources.max_forwarded_certificates() >= 2 * retained,
                    "forwarding history does not cover the retention window \
                     (participants={participants}, retention={view_retention})"
                );
                assert_eq!(
                    resources.max_future_view_distance(),
                    (retained as u64 / 8).max(3),
                    "the future-view horizon is not derived from the retention window \
                     (participants={participants}, retention={view_retention})"
                );
                assert_eq!(profile.view_retention(), ViewDelta::new(view_retention));
            }
        }
    }

    #[test]
    fn the_future_view_horizon_grows_with_retention_and_never_falls_below_three() {
        // A short window keeps the floor; a long one widens the horizon rather than pinning it at a
        // constant the deployment never chose.
        let mut previous = 0;
        for view_retention in [1u64, 8, 16, 64, 1_000, 50_000, 1_000_000] {
            let distance = profile(6, view_retention)
                .expect("derived profile is valid")
                .resources()
                .max_future_view_distance();
            assert!(distance >= 3, "retention={view_retention}");
            assert!(distance >= previous, "retention={view_retention}");
            previous = distance;
        }
        assert!(previous > 3, "the horizon never left its floor");
    }

    #[test]
    fn tuning_is_carried_through_verbatim() {
        let profile = Profile::new::<MinPk>(
            protocol(6),
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_millis(750),
                production_interval: Duration::from_millis(25),
                ..tuning(128)
            },
        )
        .expect("derived profile is valid");
        assert_eq!(profile.tuning().view_timeout, Duration::from_millis(750));
        assert_eq!(
            profile.tuning().production_interval,
            Duration::from_millis(25)
        );
        assert_eq!(profile.view_retention(), ViewDelta::new(128));
    }

    #[test]
    fn zero_duration_timers_are_rejected() {
        for (tuning, expected) in [
            (
                Tuning {
                    view_timeout: Duration::ZERO,
                    ..tuning(64)
                },
                Error::ZeroViewTimeout,
            ),
            (
                Tuning {
                    production_interval: Duration::ZERO,
                    ..tuning(64)
                },
                Error::ZeroProductionInterval,
            ),
        ] {
            assert_eq!(
                Profile::new::<MinPk>(protocol(6), Role::Observer, tuning).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn an_unset_artifact_byte_limit_is_the_codec_bound_or_one_mebibyte() {
        for (participants, limits) in [
            (11, PathLimits::new(3, 2).unwrap()),
            (200, PathLimits::new(8, 8).unwrap()),
        ] {
            let protocol = protocol_with_limits(participants, limits);
            let required = protocol
                .codec_config()
                .max_artifact_bytes::<MinPk, Sha256Digest>()
                .unwrap();
            let profile = Profile::new::<MinPk>(protocol, Role::Observer, tuning(64)).unwrap();
            assert_eq!(
                profile.resources().max_artifact_bytes(),
                required.max(MIN_ARTIFACT_BYTES).get(),
                "participants={participants}"
            );
        }
        // The small shape resolves to the floor and the large one to its codec bound.
        let small = protocol_with_limits(11, PathLimits::new(3, 2).unwrap());
        assert!(
            small
                .codec_config()
                .max_artifact_bytes::<MinPk, Sha256Digest>()
                .unwrap()
                < MIN_ARTIFACT_BYTES
        );
        let large = protocol_with_limits(200, PathLimits::new(8, 8).unwrap());
        assert!(
            large
                .codec_config()
                .max_artifact_bytes::<MinPk, Sha256Digest>()
                .unwrap()
                > MIN_ARTIFACT_BYTES
        );
    }

    #[test]
    fn an_artifact_byte_limit_whose_core_budgets_overflow_is_rejected() {
        let with_limit = |limit| Tuning {
            max_artifact_bytes: NonZeroUsize::new(limit),
            ..tuning(64)
        };
        let Err(Error::ArtifactByteLimitTooLarge { max, actual }) =
            Profile::new::<MinPk>(protocol(6), Role::Observer, with_limit(usize::MAX))
        else {
            panic!("an overflowing artifact byte limit was accepted");
        };
        assert_eq!(actual, usize::MAX);
        let profile = Profile::new::<MinPk>(protocol(6), Role::Observer, with_limit(max))
            .expect("the largest supported limit is accepted");
        assert_eq!(profile.resources().max_artifact_bytes(), max);
        assert!(matches!(
            Profile::new::<MinPk>(protocol(6), Role::Observer, with_limit(max + 1)),
            Err(Error::ArtifactByteLimitTooLarge { .. })
        ));
    }

    #[test]
    fn an_artifact_byte_limit_that_overflows_the_resolver_lane_is_rejected() {
        let protocol = protocol(6);
        let tuning = tuning(64);
        let derived = Profile::new::<MinPk>(protocol.clone(), Role::Observer, tuning)
            .unwrap()
            .resources();
        // The resolver lane holds one artifact per dependency waiter, so this many waiters make
        // it the largest lane and overflow its byte bound while the local lane still fits.
        let waiters = usize::MAX / derived.max_artifact_bytes() + 1;
        let resources = ResourceLimits {
            max_dependency_waiters: NonZeroUsize::new(waiters).unwrap(),
            ..derived
        };
        assert!(matches!(
            Profile::with_limits(protocol, Role::Observer, tuning, resources),
            Err(Error::ArtifactByteLimitTooLarge { .. })
        ));
    }

    #[test]
    fn skip_timeouts_must_exceed_the_retry_ceiling() {
        let view_timeout = Duration::from_millis(500);
        let with_skip = |skip_timeout| Tuning {
            view_timeout,
            skip_timeout,
            ..tuning(64)
        };
        for accepted in [None, Some(Duration::from_millis(1_001))] {
            assert!(
                Profile::new::<MinPk>(protocol(6), Role::Observer, with_skip(accepted)).is_ok()
            );
        }
        for rejected in [Duration::ZERO, view_timeout, Duration::from_secs(1)] {
            let error =
                Profile::new::<MinPk>(protocol(6), Role::Observer, with_skip(Some(rejected)))
                    .unwrap_err();
            assert_eq!(
                error,
                Error::SkipTimeoutTooShort {
                    retry_ceiling: Duration::from_secs(1),
                    actual: rejected,
                }
            );
            assert_eq!(
                error.to_string(),
                "skip timeout must exceed the publication retry ceiling"
            );
        }
        let resolved = |tuning| {
            Profile::new::<MinPk>(protocol(6), Role::Observer, tuning)
                .unwrap()
                .tuning()
                .skip_timeout
        };
        assert_eq!(
            resolved(with_skip(None)),
            Some(Duration::from_millis(2_500)),
            "the default window is five view timeouts"
        );
        assert_eq!(
            resolved(Tuning {
                view_timeout: Duration::from_millis(100),
                ..Tuning::default()
            }),
            Some(Duration::from_millis(500)),
            "the default window follows the view timeout it is built with"
        );
        assert_eq!(
            resolved(Tuning::new(Duration::MAX)),
            None,
            "an overflowing default window disables early timeouts"
        );
    }

    #[test]
    fn the_outbox_bound_matches_the_derived_resources() {
        for participants in [1u32, 6, 11, 50] {
            assert_eq!(
                max_outbox_effects(participants as usize).get(),
                profile(participants, 64)
                    .unwrap()
                    .resources()
                    .max_outbox_effects(),
                "participants={participants}"
            );
        }
    }

    #[test]
    fn validator_must_be_a_committee_member() {
        let outside = Role::Validator(Participant::new(6));
        assert!(matches!(
            Profile::new::<MinPk>(protocol(6), outside, tuning(64)),
            Err(Error::ValidatorOutOfRange(participant)) if participant == Participant::new(6)
        ));
    }
}
