//! Operator tuning and the local profile an engine derives from it.

use super::{Error, Protocol};
use crate::{
    multimmit::{machine::max_lane_artifacts, types::CodecConfig},
    types::{Participant, ViewDelta},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{Faults as _, N5f1};
use core::{num::NonZeroUsize, time::Duration};

/// The least anchor lag: tags this node signed reach at most two views above its current one, so
/// an anchor more than two views ahead lies above every one of them.
const MIN_ANCHOR_LAG: u64 = 2;

/// Cache slots held back for one self-certifying view proof, which no other work may consume.
const VIEW_PROOF_SLOTS: usize = 1;

/// Cache slots held back for this node's own statements in the live view: its latest vote update
/// and its leader block.
const LOCAL_CHOICE_SLOTS: usize = 2;

/// Cache slots the live view needs beyond its `n - f` messages: the parent V-QC, the leader
/// block, and the certificate those messages assemble.
const LIVE_VIEW_SLOTS: usize = 3;

/// Certificate classes forwarded per view: V-QCs and the L-QC.
const FORWARDED_CLASSES: usize = 2;

/// Cache slots budgeted per participant in each retained view: up to three live vote updates.
const VIEW_SLOTS_PER_PARTICIPANT: u64 = 3;

/// Cache slots budgeted per retained view regardless of committee size: the leader block, the
/// V-QC this node forwards, one V-QC assembled elsewhere, and the L-QC.
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

/// Smallest future-traffic horizon, in views: it covers the two views ahead that vote updates may
/// be tagged with and one self-certifying proof when the retention window is shorter than eight
/// views.
const MIN_FUTURE_VIEW_DISTANCE: u64 = 3;

/// Returns the live work a committee of `participants` bounds: uncertified future traffic,
/// in-flight verification, and publications ordering has not yet retired.
///
/// The liveness partition holds this node's own statements and one self-certifying proof.
fn live_work(participants: usize) -> u64 {
    let committee = participants.max(1) as u64;
    let quorum = N5f1::quorum(participants).max(1) as u64;
    quorum
        .saturating_add(committee.saturating_mul(LIVE_SLOTS_PER_PARTICIPANT))
        .saturating_add((LOCAL_CHOICE_SLOTS + VIEW_PROOF_SLOTS) as u64)
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
/// Producers build one block, empty or not, every `production_interval` (`theta`). Validators
/// send a vote update at most every `vote_interval` (`eta`). The view timers
/// derive from the measured one-way delay `delta_hat` and production interval `theta_hat`:
/// `delta_initial` and `theta_initial` only seed them until measurements exist, `delta_min` bounds
/// the delay estimate from below, and `timer_ceiling` bounds every timer from above, so no knob is
/// a latency the timers rely on.
/// Every internal bound (artifact cache, forwarding history) is derived from these plus the
/// committee size, so a manifest that cannot sustain operation is unrepresentable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// The least time between two vote updates for one view (`eta`). Must be non-zero.
    pub vote_interval: Duration,
    /// The least time between two of a producer's blocks (`theta`). Must be non-zero.
    pub production_interval: Duration,
    /// The one-way delay estimate used before any round trip is measured.
    pub delta_initial: Duration,
    /// The least delay estimate, so faulty validators cannot shrink the timers that derive from
    /// it to nothing. Must be non-zero and at most `delta_initial`.
    pub delta_min: Duration,
    /// Own-block endorsement round trips kept by the delay estimator. Must be non-zero.
    /// Each chain's production estimator keeps as many acceptance intervals.
    pub delta_samples: NonZeroUsize,
    /// The per-block production interval assumed for a chain before any of its acceptances is
    /// measured.
    pub theta_initial: Duration,
    /// The longest any view timer or delay estimate may grow: a robustness backstop against
    /// measurements faulty validators inflate, not a latency estimate. Must be at least
    /// `delta_initial`.
    ///
    /// Where the post-GST delay exceeds `timer_ceiling / 2.5`, views may end without a correct
    /// leader's block, so the ceiling should exceed any delay the deployment sees by a wide
    /// margin. The voter's publication retries, heartbeat, and retrieval timeout scale with it.
    pub timer_ceiling: Duration,
    /// How many views below the newest finalized view stay retained.
    ///
    /// Views more than this window below the newest finalized view are discarded, so memory and
    /// durable state stay bounded while views finalize but grow while finality stalls. It also
    /// fixes how far behind a peer may be and still be served directly from retained state.
    pub view_retention: ViewDelta,
    /// How many views below the current view vote updates are still read (`W_back`). Must be at
    /// least one, so the previous view's final votes can determine its tips.
    pub vote_window: ViewDelta,
    /// Unreadable vote updates parked per sender while their predecessors or headers are fetched.
    /// An update naming every chain that a parked update of the sender waits for is admitted past
    /// it. Twice this bound times the epoch's fault bound must stay below the dependency waiters
    /// the profile derives (four per participant), so faulty senders cannot hold every waiter.
    pub pending_updates_per_sender: NonZeroUsize,
    /// Conflicting producer headers buffered per chain height while their parent is missing.
    pub pending_branches_per_height: NonZeroUsize,
    /// How far a peer's finalization certificate must lie above the current view (`J`) for this
    /// node to anchor on it rather than catch up view by view.
    ///
    /// A node anchors on a certificate of view `v` only when `v > view + J`: it jumps to `v`,
    /// retires every earlier view, and never signs a tag below `v` again. Below that it retrieves
    /// the views it missed from its peers' retained state. `None` takes half the retention window,
    /// and at least two; a set value must be at least two.
    pub anchor_lag: Option<ViewDelta>,
    /// The largest canonical protocol artifact this deployment accepts.
    ///
    /// `None` takes the largest artifact the epoch's codec bounds admit, and at least 1 MiB. A
    /// limit below that codec bound is rejected, as is one whose derived byte budgets do not fit
    /// this target.
    pub max_artifact_bytes: Option<NonZeroUsize>,
}

impl Tuning {
    /// Returns the default tuning, with every derived limit left unset.
    pub const fn new() -> Self {
        Self {
            vote_interval: Duration::from_millis(25),
            production_interval: Duration::from_millis(23),
            delta_initial: Duration::from_millis(100),
            delta_min: Duration::from_millis(5),
            delta_samples: NonZeroUsize::new(64).unwrap(),
            theta_initial: Duration::from_millis(50),
            timer_ceiling: Duration::from_secs(10),
            view_retention: ViewDelta::new(64),
            vote_window: ViewDelta::new(2),
            pending_updates_per_sender: NonZeroUsize::new(8).unwrap(),
            pending_branches_per_height: NonZeroUsize::new(2).unwrap(),
            anchor_lag: None,
            max_artifact_bytes: None,
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
        Self::new()
    }
}

/// A [`Tuning`] with every limit it leaves unset resolved against the epoch's codec bounds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTuning {
    /// See [`Tuning::vote_interval`].
    pub(crate) vote_interval: Duration,
    /// See [`Tuning::delta_initial`].
    pub(crate) delta_initial: Duration,
    /// See [`Tuning::delta_min`].
    pub(crate) delta_min: Duration,
    /// See [`Tuning::delta_samples`].
    pub(crate) delta_samples: NonZeroUsize,
    /// See [`Tuning::theta_initial`].
    pub(crate) theta_initial: Duration,
    /// See [`Tuning::timer_ceiling`].
    pub(crate) timer_ceiling: Duration,
    /// See [`Tuning::view_retention`].
    pub(crate) view_retention: ViewDelta,
    /// See [`Tuning::vote_window`].
    pub(crate) vote_window: ViewDelta,
    /// See [`Tuning::pending_updates_per_sender`].
    pub(crate) pending_updates_per_sender: NonZeroUsize,
    /// See [`Tuning::pending_branches_per_height`].
    pub(crate) pending_branches_per_height: NonZeroUsize,
    /// See [`Tuning::anchor_lag`], resolved against the retention window.
    pub(crate) anchor_lag: ViewDelta,
    /// The largest canonical protocol artifact this deployment accepts.
    pub(crate) max_artifact_bytes: NonZeroUsize,
    /// See [`Tuning::production_interval`].
    pub(crate) production_interval: Duration,
}

impl ResolvedTuning {
    /// Resolves `tuning` with `max_artifact_bytes` the resolved artifact byte limit.
    const fn new(tuning: Tuning, max_artifact_bytes: NonZeroUsize) -> Self {
        Self {
            vote_interval: tuning.vote_interval,
            delta_initial: tuning.delta_initial,
            delta_min: tuning.delta_min,
            delta_samples: tuning.delta_samples,
            theta_initial: tuning.theta_initial,
            timer_ceiling: tuning.timer_ceiling,
            view_retention: tuning.view_retention,
            vote_window: tuning.vote_window,
            pending_updates_per_sender: tuning.pending_updates_per_sender,
            pending_branches_per_height: tuning.pending_branches_per_height,
            anchor_lag: match tuning.anchor_lag {
                Some(lag) => lag,
                None if tuning.view_retention.get() / 2 > MIN_ANCHOR_LAG => {
                    ViewDelta::new(tuning.view_retention.get() / 2)
                }
                None => ViewDelta::new(MIN_ANCHOR_LAG),
            },
            max_artifact_bytes,
            production_interval: tuning.production_interval,
        }
    }
}

/// Limits for adversarially controlled local work and reserved protocol capacity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    max_artifact_bytes: NonZeroUsize,
    max_cached_artifacts: NonZeroUsize,
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

    /// Returns the number of per-view certificate forwarding facts retained at once.
    pub const fn max_forwarded_certificates(self) -> usize {
        self.max_forwarded_certificates.get()
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

        if tuning.vote_interval.is_zero() {
            return Err(Error::ZeroVoteInterval);
        }
        if tuning.delta_min.is_zero()
            || tuning.delta_min > tuning.delta_initial
            || tuning.delta_initial > tuning.timer_ceiling
        {
            return Err(Error::DelayBounds {
                min: tuning.delta_min,
                initial: tuning.delta_initial,
                ceiling: tuning.timer_ceiling,
            });
        }
        if tuning.view_retention.get() == 0 {
            return Err(Error::ZeroViewRetention);
        }
        if tuning.vote_window.get() == 0 {
            return Err(Error::ZeroVoteWindow);
        }
        if tuning.anchor_lag.get() < MIN_ANCHOR_LAG {
            return Err(Error::AnchorLagTooSmall(tuning.anchor_lag.get()));
        }
        if tuning.production_interval.is_zero() {
            return Err(Error::ZeroProductionInterval);
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
            .checked_mul(FORWARDED_CLASSES)
            .ok_or(Error::Overflow)?;
        if resources.max_forwarded_certificates() < forwarded {
            return Err(Error::ForwardingHistoryTooSmall {
                required: forwarded,
                actual: resources.max_forwarded_certificates(),
            });
        }

        Ok(())
    }

    /// Returns the number of views the machine may hold at once while finality keeps pace: the
    /// newest finalized view's successor and the window below it.
    fn retained_views(view_retention: ViewDelta) -> Option<usize> {
        usize::try_from(view_retention.get().checked_add(1)?).ok()
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
    /// V-QC and one L-QC per retained view. Deriving them together is what makes an
    /// unsustainable manifest impossible to express. The derived values are wider than those
    /// minima because a retained view holds a whole view's working set, not a single artifact.
    ///
    /// Durable state keeps every accepted header above the base of the oldest retained view, and
    /// producers build at their own cadence, so the headers a view retains depend on the window,
    /// not on the committee: a V-QC's tips lie at most `N` above its base, so each retained view
    /// raises a chain's base by at most `N`, and a node accepts at most `D + N` above a chain's
    /// final height, which lies at most `N` above the live view's base, so at most `D + 2N` above
    /// that base, whatever the chain's producer does.
    fn derive(codec: CodecConfig, tuning: ResolvedTuning) -> ResourceLimits {
        let participants = codec.participants();
        let retained = tuning.view_retention.get().saturating_add(1);
        let committee = participants.max(1) as u64;
        let chains = codec.chains() as u64;
        let window = codec.window();

        let nonzero_usize = |value: u64| {
            NonZeroUsize::new(usize::try_from(value.max(1)).unwrap_or(usize::MAX))
                .expect("value is non-zero")
        };

        let per_view = committee
            .saturating_mul(VIEW_SLOTS_PER_PARTICIPANT)
            .saturating_add(VIEW_SLOTS_PER_VIEW)
            .saturating_add(chains.saturating_mul(u64::from(window.cap())));
        let live = live_work(participants);
        let header_lead = chains.saturating_mul(u64::from(window.max_tip_lead()));
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
            nonzero_usize(
                live.saturating_add(header_lead)
                    .saturating_add(per_view.saturating_mul(retained)),
            ),
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
                    .saturating_mul(FORWARDED_CLASSES as u64),
            ),
        )
    }

    /// Resolves `tuning` against `protocol`'s codec bounds, validates it, and derives this node's
    /// profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the tuning is invalid, when a validator role names a non-member, or
    /// when the faulty senders' pending updates could hold every dependency waiter.
    pub fn new<V: Variant>(
        protocol: Protocol<D>,
        role: Role,
        tuning: Tuning,
    ) -> Result<Self, Error> {
        let tuning = tuning.resolve::<V, D>(protocol.codec_config())?;
        let participants = protocol.codec_config().participants();
        let resources = Self::derive(protocol.codec_config(), tuning);
        Self::validate(&protocol, role, tuning, resources)?;
        // A sender holds at most its pending updates plus one awaited answer per pending update as
        // dependency waiters, so the faulty senders together must leave waiters for correct ones.
        let faulty_waiters = tuning
            .pending_updates_per_sender
            .get()
            .saturating_mul(2)
            .saturating_mul(N5f1::max_faults(participants) as usize);
        if faulty_waiters >= resources.max_dependency_waiters() {
            return Err(Error::PendingUpdatesExceedWaiters {
                pending_updates_per_sender: tuning.pending_updates_per_sender.get(),
                max_dependency_waiters: resources.max_dependency_waiters(),
            });
        }
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

    /// Returns how far above a view's base a producer header or endorsed tip is admitted: the
    /// tip lead `D + 2N` of a correct voter.
    pub(crate) const fn height_window(&self) -> u64 {
        self.protocol.codec_config().window().max_tip_lead() as u64
    }

    /// Returns the hard local resource ceilings.
    pub const fn resources(&self) -> ResourceLimits {
        self.resources
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{DEFAULT_MAX_VQC_BYTES, EpochGenesis, Window},
        types::Epoch,
    };
    use commonware_cryptography::{
        Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256::Digest as Sha256Digest,
    };
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PROFILE_TEST";

    fn protocol(participants: u32) -> Protocol<Sha256Digest> {
        protocol_with_window(participants, Window::new(1).unwrap())
    }

    fn protocol_with_window(participants: u32, window: Window) -> Protocol<Sha256Digest> {
        let genesis = EpochGenesis::new::<Sha256>(Epoch::new(7), participants as usize).unwrap();
        Protocol::new(
            NAMESPACE,
            participants as usize,
            (0..participants).map(Participant::new).collect(),
            window,
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
        let protocol = protocol_with_window(11, Window::new(3).unwrap());
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
        // Internal bounds are derived, so an operator cannot express a manifest the machine
        // rejects. If that ever stops holding, this fails for the shape that broke it.
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
    fn zero_retention_is_rejected() {
        assert_eq!(profile(6, 0).unwrap_err(), Error::ZeroViewRetention);
    }

    #[test]
    fn zero_production_interval_is_rejected() {
        let protocol = protocol_with_window(6, Window::new(3).unwrap());
        let profile = Profile::new::<MinPk>(
            protocol,
            Role::Observer,
            Tuning {
                production_interval: Duration::ZERO,
                ..tuning(64)
            },
        );
        assert_eq!(profile.unwrap_err(), Error::ZeroProductionInterval);
    }

    #[test]
    fn faulty_senders_cannot_hold_every_dependency_waiter() {
        let pending = |pending| {
            Profile::new::<MinPk>(
                protocol(11),
                Role::Observer,
                Tuning {
                    pending_updates_per_sender: NonZeroUsize::new(pending).unwrap(),
                    ..tuning(64)
                },
            )
        };
        // Eleven validators tolerate two faults and keep 44 dependency waiters.
        assert!(pending(10).is_ok());
        assert_eq!(
            pending(11).unwrap_err(),
            Error::PendingUpdatesExceedWaiters {
                pending_updates_per_sender: 11,
                max_dependency_waiters: 44,
            }
        );
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
                protocol,
                Role::Observer,
                tuning((usize::MAX / 2) as u64),
                resources,
            )
            .unwrap_err(),
            Error::Overflow
        );
    }

    #[test]
    fn derived_bounds_cover_the_retention_window() {
        // The three relationships the machine depends on: one cache slot per retained view on top
        // of a quorum of live work, one forwarded V-QC plus one forwarded L-QC per retained view,
        // and a forward horizon for uncertified traffic proportionate to the window kept behind.
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
                let codec = profile.codec();
                let window = codec.window();
                let headers = codec.chains()
                    * (window.cap() as usize * retained + window.max_tip_lead() as usize);
                assert!(
                    resources.max_cached_artifacts() >= headers,
                    "cache does not cover the accepted headers of the retention window \
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
                assert_eq!(
                    profile.tuning().view_retention,
                    ViewDelta::new(view_retention)
                );
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
                vote_interval: Duration::from_millis(15),
                ..tuning(128)
            },
        )
        .expect("derived profile is valid");
        assert_eq!(profile.tuning().vote_interval, Duration::from_millis(15));
        assert_eq!(profile.tuning().view_retention, ViewDelta::new(128));
    }

    #[test]
    fn invalid_timing_is_rejected() {
        let delay = |min, initial, ceiling| Error::DelayBounds {
            min: Duration::from_millis(min),
            initial: Duration::from_millis(initial),
            ceiling: Duration::from_millis(ceiling),
        };
        let delays = |min, initial, ceiling| Tuning {
            delta_min: Duration::from_millis(min),
            delta_initial: Duration::from_millis(initial),
            timer_ceiling: Duration::from_millis(ceiling),
            ..tuning(64)
        };
        for (tuning, expected) in [
            (
                Tuning {
                    vote_interval: Duration::ZERO,
                    ..tuning(64)
                },
                Error::ZeroVoteInterval,
            ),
            (delays(0, 10, 20), delay(0, 10, 20)),
            (delays(11, 10, 20), delay(11, 10, 20)),
            (delays(5, 21, 20), delay(5, 21, 20)),
            (
                Tuning {
                    vote_window: ViewDelta::new(0),
                    ..tuning(64)
                },
                Error::ZeroVoteWindow,
            ),
        ] {
            assert_eq!(
                Profile::new::<MinPk>(protocol(6), Role::Observer, tuning).unwrap_err(),
                expected
            );
        }
        assert!(Profile::new::<MinPk>(protocol(6), Role::Observer, delays(10, 10, 10)).is_ok());
    }

    #[test]
    fn an_unset_artifact_byte_limit_is_the_codec_bound_or_one_mebibyte() {
        // A small V-QC ceiling resolves to the floor; the default ceiling exceeds it.
        for (vqc_bytes, expected_floor) in [(64 * 1024, true), (DEFAULT_MAX_VQC_BYTES, false)] {
            let base = protocol(11);
            let parameters = Arc::unwrap_or_clone(Arc::clone(base.parameters()))
                .with_max_vqc_bytes(vqc_bytes)
                .unwrap();
            let protocol =
                Protocol::from_parameters(Arc::new(parameters), base.genesis().clone()).unwrap();
            let required = protocol
                .codec_config()
                .max_artifact_bytes::<MinPk, Sha256Digest>()
                .unwrap();
            assert_eq!(required < MIN_ARTIFACT_BYTES, expected_floor);
            let profile = Profile::new::<MinPk>(protocol, Role::Observer, tuning(64)).unwrap();
            assert_eq!(
                profile.resources().max_artifact_bytes(),
                required.max(MIN_ARTIFACT_BYTES).get(),
                "vqc_bytes={vqc_bytes}"
            );
        }
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
