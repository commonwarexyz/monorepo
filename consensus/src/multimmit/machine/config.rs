//! Immutable configuration for one local machine instance.

use crate::{
    multimmit::config::Config,
    types::{Participant, ViewDelta},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::N5f1;
use core::{marker::PhantomData, num::NonZeroUsize, time::Duration};

/// Whether this machine may authorize validator actions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// A validator acting for one ordered committee participant.
    Validator(Participant),
    /// A verifier-only replica that never authorizes signatures.
    Observer,
}

/// Logical deadlines interpreted by the attached runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Timers {
    view_timeout: Duration,
    production_interval: Duration,
}

impl Timers {
    /// Creates the logical timer policy.
    pub const fn new(view_timeout: Duration, production_interval: Duration) -> Self {
        Self {
            view_timeout,
            production_interval,
        }
    }

    /// Returns the timeout for one consensus view.
    pub const fn view_timeout(self) -> Duration {
        self.view_timeout
    }

    /// Returns the delay before retrying a producer that declined to build.
    pub const fn production_interval(self) -> Duration {
        self.production_interval
    }
}

/// The knobs an operator actually chooses for one deployment.
///
/// Every internal bound (artifact cache, forwarding history) is derived from these plus the
/// committee size, so a manifest that cannot sustain operation is unrepresentable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// How long a view may run before this node votes to nullify it.
    ///
    /// This must be non-zero and cover the paper's `2 * delta` synchrony deadline plus the
    /// deployment's bounded ingress, scheduling, and verification latency.
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
    pub max_artifact_bytes: NonZeroUsize,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(250),
            view_retention: ViewDelta::new(64),
            max_artifact_bytes: NonZeroUsize::new(1024 * 1024).expect("one mebibyte is non-zero"),
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
    pub const fn new(
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

    /// Returns the maximum number of retained artifact records.
    pub const fn max_cached_artifacts(self) -> usize {
        self.max_cached_artifacts.get()
    }

    /// Returns the pool budget for unfinalized leaders and the normal certified-view window.
    ///
    /// Quorum-authenticated pools may exceed this budget while ordering is stalled. They remain
    /// retained within the configured diagnostic view window.
    pub const fn max_finality_pools(self) -> usize {
        self.max_finality_pools.get()
    }

    /// Sets a distinct finality-pool budget.
    pub const fn with_max_finality_pools(mut self, max_finality_pools: NonZeroUsize) -> Self {
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

    /// Returns the largest distance accepted for uncertified future-view traffic.
    pub const fn max_future_view_distance(self) -> u64 {
        self.max_future_view_distance
    }

    /// Returns the maximum number of retained future-view artifacts.
    pub const fn max_future_artifacts(self) -> usize {
        self.max_future_artifacts.get()
    }

    /// Returns the ceiling for untrusted waiters and remembered dependency failures.
    pub const fn max_dependency_waiters(self) -> usize {
        self.max_dependency_waiters.get()
    }

    /// Returns the maximum number of durable external actions awaiting acknowledgement.
    pub const fn max_outbox_effects(self) -> usize {
        self.max_outbox_effects.get()
    }

    /// Returns the number of exact per-view certificate forwarding facts retained at once.
    pub const fn max_forwarded_certificates(self) -> usize {
        self.max_forwarded_certificates.get()
    }

    /// Sets the ceiling for exact V-QC and nullification forwarding facts.
    ///
    /// The paper defines first forwarding independently for both certificate classes, so a
    /// retained view can hold one fact of each class.
    pub const fn with_max_forwarded_certificates(
        mut self,
        max_forwarded_certificates: NonZeroUsize,
    ) -> Self {
        self.max_forwarded_certificates = max_forwarded_certificates;
        self
    }
}

/// Complete local construction profile for one machine instance.
///
/// The profile selects cryptographic types and resource policy without prescribing an application
/// block format or creating a second protocol manifest.
#[derive(Debug)]
pub struct Profile<H: Hasher, V: Variant> {
    protocol: Config<H::Digest>,
    role: Role,
    timers: Timers,
    view_retention: ViewDelta,
    resources: ResourceLimits,
    marker: PhantomData<V>,
}

impl<H: Hasher, V: Variant> Clone for Profile<H, V> {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            role: self.role,
            timers: self.timers,
            view_retention: self.view_retention,
            resources: self.resources,
            marker: PhantomData,
        }
    }
}

impl<H: Hasher, V: Variant> Profile<H, V> {
    /// Checks the bounds a profile must satisfy, whether derived or supplied by a test.
    fn validate(
        protocol: &Config<H::Digest>,
        role: Role,
        timers: Timers,
        view_retention: ViewDelta,
        resources: ResourceLimits,
    ) -> Result<(), ProfileError> {
        let participants = protocol.codec_config().participants();
        if let Role::Validator(participant) = role
            && participant.get() as usize >= participants
        {
            return Err(ProfileError::ValidatorOutOfRange(participant));
        }

        if timers.view_timeout().is_zero() {
            return Err(ProfileError::ZeroViewTimeout);
        }
        if timers.production_interval().is_zero() {
            return Err(ProfileError::ZeroProductionInterval);
        }
        if view_retention.get() == 0 {
            return Err(ProfileError::ZeroViewRetention);
        }

        // The live view retains its parent V-QC and leader while collecting n-f messages, then
        // reserves one slot for the resulting certificate. Every view below it that is still
        // retained needs at least its exit proof.
        let required = N5f1::l_quorum(participants) as usize + 3;
        let actual = resources.max_cached_artifacts();
        if actual < required {
            return Err(ProfileError::ArtifactCacheTooSmall { required, actual });
        }
        let retention = ProfileError::RetentionExceedsArtifactCache {
            view_retention: view_retention.get(),
            actual,
        };
        let retained = Self::retained_views(view_retention).ok_or(retention.clone())?;
        let required = required.checked_add(retained - 1).ok_or(retention)?;
        if actual < required {
            return Err(ProfileError::ArtifactCacheTooSmall { required, actual });
        }
        let forwarded = retained
            .checked_mul(2)
            .ok_or(ProfileError::ForwardingHistoryTooSmall {
                required: usize::MAX,
                actual: resources.max_forwarded_certificates(),
            })?;
        if resources.max_forwarded_certificates() < forwarded {
            return Err(ProfileError::ForwardingHistoryTooSmall {
                required: forwarded,
                actual: resources.max_forwarded_certificates(),
            });
        }

        // One pinned slot covers each locally retained or admissible future view. The remaining
        // protected partition holds one liveness primary for each of f faulty owners plus one
        // correct owner.
        let pinned = Self::required_pinned_finality_pools(view_retention, resources).ok_or(
            ProfileError::FinalityPoolCapacityTooSmall {
                required: usize::MAX,
                actual: resources.max_finality_pools(),
            },
        )?;
        let required = pinned
            .checked_add(participants.saturating_sub(1) / 5 + 1)
            .ok_or(ProfileError::FinalityPoolCapacityTooSmall {
                required: usize::MAX,
                actual: resources.max_finality_pools(),
            })?;
        if resources.max_finality_pools() < required {
            return Err(ProfileError::FinalityPoolCapacityTooSmall {
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
    #[cfg(any(test, feature = "mocks"))]
    pub fn with_limits(
        protocol: Config<H::Digest>,
        role: Role,
        tuning: Tuning,
        resources: ResourceLimits,
    ) -> Result<Self, ProfileError> {
        let (timers, _) = Self::derive(protocol.codec_config().participants(), tuning);
        Self::validate(&protocol, role, timers, tuning.view_retention, resources)?;
        Ok(Self {
            protocol,
            role,
            timers,
            view_retention: tuning.view_retention,
            resources,
            marker: PhantomData,
        })
    }

    /// Derives every internal bound from the committee size and the operator's tuning.
    ///
    /// The relationships here are the ones the validation below enforces: the artifact cache must
    /// cover live work plus a slot per retained view, and the forwarding history must cover one
    /// V-QC and one nullification per retained view. Deriving them together is what makes an
    /// unsustainable manifest impossible to express. The derived values are wider than those
    /// minima because a retained view holds a whole view's working set, not a single artifact.
    fn derive(participants: usize, tuning: Tuning) -> (Timers, ResourceLimits) {
        let retained = Self::retained_views(tuning.view_retention).unwrap_or(usize::MAX) as u64;
        let committee = participants.max(1) as u64;
        let quorum = N5f1::l_quorum(participants).max(1) as u64;

        let nonzero_usize =
            |value: u64| NonZeroUsize::new(value.max(1) as usize).expect("value is non-zero");

        let timers = Timers::new(tuning.view_timeout, tuning.production_interval);

        // One view holds at most a block, a data-availability certificate, and a view message per
        // chain, plus the proposal and the certificate that closes it.
        let per_view = committee.saturating_mul(4).saturating_add(4);
        // Live work is bounded by the committee: uncertified future traffic, in-flight
        // verification, and the publications ordering has not yet retired.
        let live = quorum
            .saturating_add(committee.saturating_mul(48))
            .saturating_add(3);
        let future = committee.saturating_mul(8);
        let resources = ResourceLimits::new(
            tuning.max_artifact_bytes,
            nonzero_usize(live.saturating_add(per_view.saturating_mul(retained))),
            nonzero_usize(committee.saturating_mul(8)),
            nonzero_usize(committee.saturating_mul(8)),
            3,
            nonzero_usize(future),
            nonzero_usize(committee.saturating_mul(4)),
            nonzero_usize(live),
            // A certificate for a view above the current one is forwarded before that view is
            // reached, so the bounded future-view index needs its own room here.
            nonzero_usize(retained.saturating_add(future).saturating_mul(2)),
        );
        (timers, resources)
    }

    /// Validates and creates a local machine profile.
    pub fn new(
        protocol: Config<H::Digest>,
        role: Role,
        tuning: Tuning,
    ) -> Result<Self, ProfileError> {
        let required = protocol
            .codec_config()
            .encoded_bounds::<V, H::Digest>()
            .map_err(|_| ProfileError::EncodedSizeOverflow)?
            .max_artifact_bytes();
        let actual = tuning.max_artifact_bytes.get();
        if actual < required {
            return Err(ProfileError::ArtifactByteLimitTooSmall { required, actual });
        }

        let (timers, resources) = Self::derive(protocol.codec_config().participants(), tuning);
        Self::validate(&protocol, role, timers, tuning.view_retention, resources)?;
        Ok(Self {
            protocol,
            role,
            timers,
            view_retention: tuning.view_retention,
            resources,
            marker: PhantomData,
        })
    }

    /// Returns the validated protocol configuration.
    pub const fn protocol(&self) -> &Config<H::Digest> {
        &self.protocol
    }

    /// Returns the local node role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the logical timer policy.
    pub const fn timers(&self) -> Timers {
        self.timers
    }

    /// Returns how many views below the current view stay retained.
    pub const fn view_retention(&self) -> ViewDelta {
        self.view_retention
    }

    /// Returns the hard local resource ceilings.
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }

    pub(crate) fn pinned_finality_pools(&self) -> usize {
        Self::required_pinned_finality_pools(self.view_retention, self.resources)
            .expect("validated finality retention fits usize")
    }
}

/// An invalid local machine profile.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The epoch's encoded maxima cannot be represented on this target.
    #[error("encoded protocol maximum exceeds usize")]
    EncodedSizeOverflow,
    /// The artifact byte limit cannot admit every bounded protocol artifact.
    #[error("artifact byte limit {actual} is below the required minimum {required}")]
    ArtifactByteLimitTooSmall { required: usize, actual: usize },
    /// The view timer would fire continuously and cannot satisfy the synchrony assumption.
    #[error("view timeout must be greater than zero")]
    ZeroViewTimeout,
    /// A producer retry loop would run continuously.
    #[error("production interval must be greater than zero")]
    ZeroProductionInterval,
    /// The just-completed view must remain available for votes delivered within the synchrony bound.
    #[error("view retention must be greater than zero")]
    ZeroViewRetention,
    /// The validator identity is not in the configured ordered committee.
    #[error("validator participant {0} is outside the configured committee")]
    ValidatorOutOfRange(Participant),
    /// The artifact cache cannot retain live work and the retention window.
    #[error("artifact cache capacity {actual} is below the required minimum {required}")]
    ArtifactCacheTooSmall { required: usize, actual: usize },
    /// The retention window cannot be represented by the artifact cache.
    #[error("view retention {view_retention} exceeds artifact cache capacity {actual}")]
    RetentionExceedsArtifactCache { view_retention: u64, actual: usize },
    /// The forwarding history cannot retain both exit-certificate classes for every retained view.
    #[error("forwarding history capacity {actual} is below the required minimum {required}")]
    ForwardingHistoryTooSmall { required: usize, actual: usize },
    /// The finality pool partition cannot retain certificates and `f+1` live owners.
    #[error("finality pool capacity {actual} is below the required minimum {required}")]
    FinalityPoolCapacityTooSmall { required: usize, actual: usize },
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
