//! Ingress actor configuration and buffering bounds.

use crate::{
    multimmit::{
        config::Profile,
        types::{CodecConfig, EncodedBounds},
    },
    types::Epoch,
};
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use commonware_utils::{Faults as _, N5f1, ordered::Set};
use std::{num::NonZeroUsize, sync::Arc};

/// Smallest byte bound of one lane.
///
/// Covers the small committee shapes where a maximum-size group is a few kilobytes.
const MIN_LANE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum-size groups one peer share must hold.
///
/// A correct peer sends a proposal carrying its parent certificate, which is one whole group, and
/// the next arrives before the voter has drained the first.
const PEER_SHARE_GROUPS: usize = 2;

/// Explicit ingress buffering bounds.
///
/// These bounds are hard ceilings enforced before any reliable mailbox. Saturation drops hostile
/// ingress with typed accounting instead of growing an unbounded queue.
#[derive(Copy, Clone, Debug)]
pub(crate) struct IngressLimits {
    /// Target artifacts forwarded in one data-plane observation cohort.
    ///
    /// Consensus and certificate plane cohorts are further capped at `view_cohort_items`. An
    /// indivisible parent-and-proposal group may exceed either target by one artifact.
    pub(crate) cohort_items: NonZeroUsize,
    /// Target artifacts forwarded in one consensus or certificate plane cohort.
    ///
    /// The voter merges queued view-critical cohorts only up to this bound.
    pub(crate) view_cohort_items: NonZeroUsize,
    /// Maximum artifacts buffered per ingress lane.
    pub(crate) lane_items: NonZeroUsize,
    /// Maximum encoded artifact bytes buffered per ingress lane.
    pub(crate) lane_bytes: NonZeroUsize,
}

impl IngressLimits {
    /// Artifacts selected into one consensus or certificate plane cohort.
    ///
    /// These cohorts stay small enough that a view-critical verdict never waits out a large
    /// batch's cryptography.
    pub(crate) const VIEW_COHORT_ITEMS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

    /// Small bounds that tests start from and override field by field.
    #[cfg(test)]
    pub(crate) const TEST: Self = Self {
        cohort_items: NonZeroUsize::new(8).unwrap(),
        view_cohort_items: Self::VIEW_COHORT_ITEMS,
        lane_items: NonZeroUsize::new(16).unwrap(),
        lane_bytes: NonZeroUsize::new(64 * 1024).unwrap(),
    };

    /// Derives the bounds from the profile's committee, codec shape, and resource ceilings.
    pub(crate) fn from_profile<V: Variant, D: Digest>(profile: &Profile<D>) -> Self {
        let resources = profile.resources();
        let codec = profile.codec();
        let fault_domains = (N5f1::max_faults(codec.participants()) + 1) as usize;
        let max_ingress_group_bytes = codec
            .encoded_bounds::<V, D>()
            .expect("profile validated encoded protocol bounds")
            .max_ingress_group_bytes();
        Self {
            cohort_items: NonZeroUsize::new(resources.max_verification_batch()).expect("non-zero"),
            view_cohort_items: Self::VIEW_COHORT_ITEMS,
            lane_items: NonZeroUsize::new(resources.max_cached_artifacts()).expect("non-zero"),
            // Each fault domain's share must hold `PEER_SHARE_GROUPS` maximum-size groups (see
            // `peer_share`).
            lane_bytes: NonZeroUsize::new(
                max_ingress_group_bytes
                    .saturating_mul(PEER_SHARE_GROUPS)
                    .saturating_mul(fault_domains)
                    .max(MIN_LANE_BYTES),
            )
            .expect("ingress byte floor is non-zero"),
        }
    }

    /// Returns one peer's item and byte share of a lane in a committee of `participants`.
    ///
    /// Splitting a lane across `f + 1` fault domains leaves a whole share for a correct peer no
    /// matter how the faulty ones fill theirs. The share is only useful if it holds more than one
    /// maximum-size group, which is what `lane_bytes` is sized for.
    pub(crate) fn peer_share(self, participants: usize) -> (usize, usize) {
        let fault_domains = (N5f1::max_faults(participants) + 1) as usize;
        (
            self.lane_items.get() / fault_domains,
            self.lane_bytes.get() / fault_domains,
        )
    }
}

/// Configuration for the ingress actor.
pub(crate) struct Config<P: PublicKey, T, C> {
    /// The engine's immutable epoch; frames naming another epoch are dropped.
    pub(crate) epoch: Epoch,
    /// The identity-key committee, so a vote update whose claimed signer is not the sending peer
    /// is dropped. Honest updates are sent only by their signer.
    pub(crate) participants: Arc<Set<P>>,
    /// Execution strategy for data-plane decoding and identification.
    pub(crate) strategy: T,
    /// Execution strategy for consensus- and certificate-plane decoding and identification.
    pub(crate) critical_strategy: C,
    /// Bounded decode configuration for the epoch.
    pub(crate) codec: CodecConfig,
    /// Encoded frame bounds for each plane, derived from `codec`.
    pub(crate) bounds: EncodedBounds,
    /// Hard ingress buffering bounds.
    pub(crate) limits: IngressLimits,
    /// Control mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
    /// Maximum observation cohorts awaiting voter consumption.
    ///
    /// Ready ingress completions are grouped into bounded cohorts and forwarded as soon as credit
    /// is free. While every credit is in flight, ingress accumulates in the fair lanes. The voter
    /// merges queued bulk cohorts up to one verification batch while keeping critical cohorts
    /// intact, so credits beyond one batch only move artifacts out of the fair lanes into a queue
    /// a single machine step cannot consume.
    pub(crate) observation_capacity: NonZeroUsize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::{Protocol, Role, Tuning},
            mocks::keys::test_config,
            types::Window,
        },
        types::Participant,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };

    /// Committee sizes and window caps: the deployed shape first, then the shapes the behavioural
    /// tests run at.
    const SHAPES: [(u32, u32); 5] = [(50, 16), (11, 4), (7, 2), (6, 1), (1, 1)];

    /// Builds an epoch configuration of `participants` producers without generating keys.
    fn protocol(participants: u32, cap: u32) -> Protocol<Sha256Digest> {
        test_config(
            1,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_INGRESS_SHAPE_TEST",
            participants,
            (0..participants).map(Participant::new).collect(),
            Window::new(cap).unwrap(),
        )
    }

    fn observer_profile(protocol: Protocol<Sha256Digest>) -> Profile<Sha256Digest> {
        let bounds = protocol
            .codec_config()
            .encoded_bounds::<MinPk, Sha256Digest>()
            .unwrap();
        Profile::new::<MinPk>(
            protocol,
            Role::Observer,
            Tuning {
                max_artifact_bytes: NonZeroUsize::new(bounds.max_artifact_bytes()),
                ..Tuning::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn lanes_reserve_two_codec_groups_per_fault_domain() {
        for (participants, cap) in SHAPES {
            let protocol = protocol(participants, cap);
            let group = protocol
                .codec_config()
                .encoded_bounds::<MinPk, Sha256Digest>()
                .unwrap()
                .max_ingress_group_bytes();
            let fault_domains = (N5f1::max_faults(participants) + 1) as usize;
            let limits = IngressLimits::from_profile::<MinPk, _>(&observer_profile(protocol));

            assert_eq!(
                limits.lane_bytes.get(),
                group
                    .saturating_mul(PEER_SHARE_GROUPS)
                    .saturating_mul(fault_domains)
                    .max(MIN_LANE_BYTES),
            );
            assert_eq!(limits.view_cohort_items, IngressLimits::VIEW_COHORT_ITEMS);
        }
    }

    #[test]
    fn peer_share_holds_two_maximum_groups_at_every_shape() {
        for (participants, cap) in SHAPES {
            let protocol = protocol(participants, cap);
            let group = protocol
                .codec_config()
                .encoded_bounds::<MinPk, Sha256Digest>()
                .unwrap()
                .max_ingress_group_bytes();
            let limits = IngressLimits::from_profile::<MinPk, _>(&observer_profile(protocol));
            let (peer_items, peer_bytes) = limits.peer_share(participants as usize);

            assert!(
                peer_bytes >= group.saturating_mul(PEER_SHARE_GROUPS),
                "a correct peer holds fewer than two maximum groups \
                 (participants={participants}, cap={cap}): {peer_bytes} against {group}"
            );
            assert!(
                peer_items >= PEER_SHARE_GROUPS,
                "a correct peer holds fewer than two artifacts (participants={participants})"
            );
            assert!(limits.lane_bytes.get() >= peer_bytes);
        }
    }
}
