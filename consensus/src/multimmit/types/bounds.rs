//! Encoded-size maxima of bounded protocol objects under one [`CodecConfig`].
//!
//! Each protocol object states its largest encoding beside its `Write` impl as
//! `max_encode_size`. This module holds the varint arithmetic those bounds share and composes them
//! into [`EncodedBounds`]: the artifact, ingress-group, and network-frame ceilings enforced before
//! decoding. All arithmetic is checked, and `None` means the epoch's shape does not fit the wire
//! format on this target.

use super::{
    CodecConfig, DaCertificate, DaVote, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock,
    SignedTransactionBlock, Vote, Vqc,
};
use commonware_codec::{EncodeSize as _, FixedSize as _, varint::UInt};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::num::NonZeroUsize;

/// Largest encoding of a `u64` varint.
pub(super) const MAX_U64_VARINT_SIZE: usize = 10;

/// Values at or above each boundary need one more varint byte than values below it.
pub(super) const VARINT_BOUNDARIES: [usize; 4] = [1 << 7, 1 << 14, 1 << 21, 1 << 28];

/// Encoded maxima derived from an immutable epoch codec configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedBounds {
    max_artifact_bytes: usize,
    max_ingress_group_bytes: usize,
    max_data_frame_bytes: usize,
    max_consensus_frame_bytes: usize,
    max_certificate_frame_bytes: usize,
}

impl EncodedBounds {
    pub(crate) const fn max_artifact_bytes(self) -> usize {
        self.max_artifact_bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn max_ingress_group_bytes(self) -> usize {
        self.max_ingress_group_bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn max_data_frame_bytes(self) -> usize {
        self.max_data_frame_bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn max_consensus_frame_bytes(self) -> usize {
        self.max_consensus_frame_bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn max_certificate_frame_bytes(self) -> usize {
        self.max_certificate_frame_bytes
    }
}

impl CodecConfig {
    /// Returns the largest canonical artifact this configuration can encode, or `None` when the
    /// committee's bounds do not fit the wire format.
    ///
    /// A deployment's artifact byte limit must cover this value: a V-QC whose votes all deviate
    /// carries every voter's positions and extensions for every chain, so the figure grows with
    /// participants, chains, pipeline depth, and extension bound together.
    pub fn max_artifact_bytes<V: Variant, D: Digest>(self) -> Option<NonZeroUsize> {
        NonZeroUsize::new(self.encoded_bounds::<V, D>()?.max_artifact_bytes())
    }

    /// Computes encoded upper bounds for this epoch's bounded protocol objects.
    pub(crate) fn encoded_bounds<V: Variant, D: Digest>(self) -> Option<EncodedBounds> {
        let sizes = ProtocolSizes::new::<V, D>(self)?;
        let envelope = checked_sum(&[1, MAX_U64_VARINT_SIZE])?;

        let max_artifact_bytes = sizes.max_artifact();
        let proposal_group = checked_sum(&[sizes.vqc, sizes.signed_leader])?;
        let max_ingress_group_bytes = max_artifact_bytes.max(proposal_group);
        let max_data_frame_bytes = checked_sum(&[
            envelope,
            1,
            sizes
                .signed_transaction
                .max(sizes.da_vote)
                .max(sizes.da_certificate),
        ])?;
        let proposal = checked_sum(&[1, proposal_group])?;
        let max_consensus_frame_bytes = checked_sum(&[
            envelope,
            1,
            proposal
                .max(sizes.vote)
                .max(sizes.no_vote)
                .max(sizes.nullify),
        ])?;
        let max_certificate_frame_bytes = checked_sum(&[
            envelope,
            1,
            sizes.nullification.max(sizes.vqc).max(sizes.lqc),
        ])?;

        Some(EncodedBounds {
            max_artifact_bytes,
            max_ingress_group_bytes,
            max_data_frame_bytes,
            max_consensus_frame_bytes,
            max_certificate_frame_bytes,
        })
    }
}

/// The largest encoding of every artifact a network plane carries.
struct ProtocolSizes {
    signed_transaction: usize,
    da_vote: usize,
    da_certificate: usize,
    signed_leader: usize,
    vote: usize,
    no_vote: usize,
    nullify: usize,
    nullification: usize,
    vqc: usize,
    lqc: usize,
}

impl ProtocolSizes {
    fn new<V: Variant, D: Digest>(codec: CodecConfig) -> Option<Self> {
        Some(Self {
            signed_transaction: SignedTransactionBlock::<V, D>::max_encode_size(codec)?,
            da_vote: DaVote::<V, D>::max_encode_size(codec)?,
            da_certificate: DaCertificate::<V, D>::max_encode_size(codec)?,
            signed_leader: SignedLeaderBlock::<V, D>::max_encode_size(codec)?,
            vote: Vote::<V, D>::max_encode_size(codec)?,
            no_vote: NoVote::<V>::max_encode_size(codec)?,
            nullify: Nullify::<V>::max_encode_size(codec)?,
            nullification: Nullification::<V>::max_encode_size()?,
            vqc: Vqc::<V, D>::max_encode_size(codec)?,
            lqc: Lqc::<V, D>::max_encode_size(codec)?,
        })
    }

    fn max_artifact(&self) -> usize {
        [
            self.signed_transaction,
            self.da_vote,
            self.da_certificate,
            self.signed_leader,
            self.vote,
            self.no_vote,
            self.nullify,
            self.nullification,
            self.vqc,
            self.lqc,
        ]
        .into_iter()
        .max()
        .expect("artifact set is non-empty")
    }
}

/// Returns the sum of `values`.
pub(super) fn checked_sum(values: &[usize]) -> Option<usize> {
    values
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(*value))
}

/// Returns `left * right`.
pub(super) const fn checked_product(left: usize, right: usize) -> Option<usize> {
    left.checked_mul(right)
}

/// Returns the encoded size of a length or index `value`, which the wire format caps at `u32`.
pub(super) fn encoded_len(value: usize) -> Option<usize> {
    let value = u32::try_from(value).ok()?;
    Some(UInt(value).encode_size())
}

/// Returns the encoded size of `count` items of `item_size` bytes behind a length prefix.
pub(super) fn encoded_vec(count: usize, item_size: usize) -> Option<usize> {
    checked_sum(&[encoded_len(count)?, checked_product(count, item_size)?])
}

/// Returns the encoded size of the largest index below `count`.
pub(super) fn max_index_width(count: usize) -> Option<usize> {
    encoded_len(count - 1)
}

/// Returns the encoded size of a signer bitmap over `participants`.
pub(super) fn signers_size(participants: usize) -> Option<usize> {
    // Signers wraps BitMap<1>, which prefixes its bit count with a fixed-width u64.
    checked_sum(&[u64::SIZE, participants.div_ceil(8)])
}

/// Returns the total encoded size of every index below `count`.
pub(super) fn encoded_index_sum(count: usize) -> Option<usize> {
    let count = u64::try_from(count).ok()?;
    let ends = VARINT_BOUNDARIES
        .map(|boundary| boundary as u64)
        .into_iter()
        .chain([u64::from(u32::MAX) + 1]);
    let mut start = 0u64;
    let mut total = 0usize;
    for (width, end) in (1..).zip(ends) {
        let indices = usize::try_from(count.min(end).saturating_sub(start)).ok()?;
        total = checked_sum(&[total, checked_product(indices, width)?])?;
        if count <= end {
            return Some(total);
        }
        start = end;
    }
    None
}

/// Returns the total encoded size of the `count` largest indices below `participants`.
pub(super) fn largest_index_width_sum(participants: usize, count: usize) -> Option<usize> {
    let first = participants.checked_sub(count)?;
    encoded_index_sum(participants)?.checked_sub(encoded_index_sum(first)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{
            Anchor, Ballot, CertificateId, ChainId, ChainProposal, ConflictingVote, DaCertificate,
            DigestedLeader, Extension, LeaderBlock, Lqc, PathLimits, Position, Tally,
            TransactionBlockHeader, VoteBody, Vqc,
        },
        types::{Epoch, Height, Participant, Round, View},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Hasher, Sha256,
        bls12381::{
            certificate::threshold,
            primitives::{
                ops::aggregate,
                variant::{MinPk, MinSig},
            },
        },
        certificate::Signers,
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Additive;

    fn assert_constructed_certificate_maxima<V: Variant>() {
        for (participants, chains, depth, bound) in [
            (1, 1, 1, 0),
            (6, 6, 2, 0),
            (6, 6, 2, 2),
            (6, 129, 129, 1),
            (129, 1, 1, 1),
        ] {
            let config =
                CodecConfig::new(participants, chains, PathLimits::new(depth, bound).unwrap())
                    .unwrap();
            let round = Round::new(Epoch::new(u64::MAX), View::new(u64::MAX));
            let digest = Sha256::hash(&[b"maximal certificate"]);
            let proposals = (0..chains)
                .map(|chain| {
                    let chain = ChainId::new(chain as u32);
                    let header = TransactionBlockHeader::new(
                        round.epoch(),
                        chain,
                        Height::new(u64::MAX - u64::from(depth) - u64::from(bound)),
                        digest,
                        digest,
                    )
                    .unwrap();
                    let anchor = Anchor::Certificate(DaCertificate::<V, _>::new(
                        header,
                        threshold::Certificate::new(V::Signature::zero()),
                    ));
                    ChainProposal::new(
                        chain,
                        anchor,
                        vec![digest; depth as usize],
                        config.pipeline_depth(),
                    )
                    .unwrap()
                })
                .collect();
            let leader = LeaderBlock::<V, _>::new(
                round,
                CertificateId::new(digest),
                digest,
                proposals,
                config,
            )
            .unwrap();
            let extensions = |signer: usize| {
                (0..chains)
                    .map(|chain| {
                        Extension::new(
                            vec![
                                Sha256::hash(&[&signer.to_be_bytes(), &chain.to_be_bytes()]);
                                bound as usize
                            ],
                            bound as usize,
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
            };
            let tally = |count: usize| {
                Tally::from_votes(
                    DigestedLeader::new::<Sha256>(&leader),
                    (participants - count..participants).map(|signer| {
                        (
                            Participant::from_usize(signer),
                            VoteBody::for_leader(
                                DigestedLeader::new::<Sha256>(&leader),
                                vec![Position::new(depth - 1); chains],
                                extensions(signer),
                                config,
                            )
                            .unwrap(),
                        )
                    }),
                    config,
                )
                .unwrap()
            };
            let lqc = Lqc::new(
                leader.clone(),
                tally(config.view_quorum()),
                aggregate::Signature::zero(),
                config,
            )
            .unwrap();
            let sizes = ProtocolSizes::new::<V, Sha256Digest>(config).unwrap();
            assert!(
                lqc.encode().len() <= sizes.lqc,
                "participants={participants} chains={chains} depth={depth} bound={bound}"
            );
            let largest_vqc = (config.designation_quorum()..=participants)
                .map(|count| {
                    let conflicting = (0..participants - count)
                        .map(|signer| {
                            let ballot = Ballot::new(
                                digest,
                                vec![Position::new(depth); chains],
                                extensions(signer),
                                config,
                            )
                            .unwrap();
                            ConflictingVote::new(Participant::from_usize(signer), ballot, config)
                                .unwrap()
                        })
                        .collect();
                    Vqc::new(
                        leader.clone(),
                        tally(count),
                        Signers::new(u32::try_from(participants).unwrap(), []).unwrap(),
                        conflicting,
                        aggregate::Signature::zero(),
                        config,
                    )
                    .unwrap()
                    .encode()
                    .len()
                })
                .max()
                .unwrap();
            assert!(
                largest_vqc <= sizes.vqc,
                "participants={participants} chains={chains} depth={depth} bound={bound}"
            );
        }
    }

    #[test]
    fn encoded_bounds_cover_constructed_dense_certificates() {
        assert_constructed_certificate_maxima::<MinPk>();
        assert_constructed_certificate_maxima::<MinSig>();
    }

    /// Committee shapes, and for each the per-artifact maxima and then the encoded bounds.
    type Recorded = [((usize, usize, u32, u32), [usize; 10], [usize; 5]); 7];

    fn assert_recorded<V: Variant>(recorded: Recorded) {
        for ((participants, chains, depth, bound), artifacts, bounds) in recorded {
            let codec =
                CodecConfig::new(participants, chains, PathLimits::new(depth, bound).unwrap())
                    .unwrap();
            let sizes = ProtocolSizes::new::<V, Sha256Digest>(codec).unwrap();
            assert_eq!(
                [
                    sizes.signed_transaction,
                    sizes.da_vote,
                    sizes.da_certificate,
                    sizes.signed_leader,
                    sizes.vote,
                    sizes.no_vote,
                    sizes.nullify,
                    sizes.nullification,
                    sizes.vqc,
                    sizes.lqc,
                ],
                artifacts,
                "participants={participants} chains={chains} depth={depth} bound={bound}"
            );
            let encoded = codec.encoded_bounds::<V, Sha256Digest>().unwrap();
            assert_eq!(
                [
                    encoded.max_artifact_bytes(),
                    encoded.max_ingress_group_bytes(),
                    encoded.max_data_frame_bytes(),
                    encoded.max_consensus_frame_bytes(),
                    encoded.max_certificate_frame_bytes(),
                ],
                bounds,
                "participants={participants} chains={chains} depth={depth} bound={bound}"
            );
        }
    }

    #[test]
    fn encoded_bounds_match_the_wire_format() {
        // Any change here changes which frames an engine admits, which is a wire format change.
        assert_recorded::<MinPk>([
            (
                (1, 1, 1, 0),
                [182, 182, 181, 397, 153, 117, 117, 116, 424, 414],
                [424, 821, 194, 834, 436],
            ),
            (
                (4, 2, 2, 1),
                [182, 182, 181, 676, 219, 117, 117, 116, 1079, 991],
                [1079, 1755, 194, 1768, 1091],
            ),
            (
                (6, 6, 2, 2),
                [182, 182, 181, 1664, 547, 117, 117, 116, 4217, 3748],
                [4217, 5881, 194, 5894, 4229],
            ),
            (
                (11, 7, 64, 32),
                [182, 182, 181, 15799, 7333, 117, 117, 116, 95140, 80651],
                [95140, 110939, 194, 110952, 95152],
            ),
            (
                (50, 50, 4, 1),
                [182, 182, 181, 15732, 1851, 117, 117, 116, 110766, 93623],
                [110766, 126498, 194, 126511, 110778],
            ),
            (
                (129, 3, 129, 1),
                [183, 183, 181, 13119, 257, 118, 118, 116, 30204, 25618],
                [30204, 43323, 195, 43336, 30216],
            ),
            (
                (200, 200, 8, 8),
                [
                    184, 184, 182, 88056, 51754, 118, 118, 116, 10637127, 8579882,
                ],
                [10637127, 10725183, 196, 10725196, 10637139],
            ),
        ]);
        assert_recorded::<MinSig>([
            (
                (1, 1, 1, 0),
                [134, 134, 133, 301, 105, 69, 69, 68, 328, 318],
                [328, 629, 146, 642, 340],
            ),
            (
                (4, 2, 2, 1),
                [134, 134, 133, 532, 171, 69, 69, 68, 935, 847],
                [935, 1467, 146, 1480, 947],
            ),
            (
                (6, 6, 2, 2),
                [134, 134, 133, 1328, 499, 69, 69, 68, 3881, 3412],
                [3881, 5209, 146, 5222, 3893],
            ),
            (
                (11, 7, 64, 32),
                [134, 134, 133, 15415, 7285, 69, 69, 68, 94756, 80267],
                [94756, 110171, 146, 110184, 94768],
            ),
            (
                (50, 50, 4, 1),
                [134, 134, 133, 13284, 1803, 69, 69, 68, 108318, 91175],
                [108318, 121602, 146, 121615, 108330],
            ),
            (
                (129, 3, 129, 1),
                [135, 135, 133, 12927, 209, 70, 70, 68, 30012, 25426],
                [30012, 42939, 147, 42952, 30024],
            ),
            (
                (200, 200, 8, 8),
                [136, 136, 134, 78408, 51706, 70, 70, 68, 10627479, 8570234],
                [10627479, 10705887, 148, 10705900, 10627491],
            ),
        ]);
    }

    #[test]
    fn checked_encoded_bounds_reject_overflow_without_allocating() {
        let codec = CodecConfig::new(
            u32::MAX as usize,
            u32::MAX as usize,
            PathLimits::new(u32::MAX, u32::MAX).unwrap(),
        )
        .unwrap();

        assert_eq!(codec.encoded_bounds::<MinPk, Sha256Digest>(), None);
        assert_eq!(codec.encoded_bounds::<MinSig, Sha256Digest>(), None);
        assert_eq!(codec.max_artifact_bytes::<MinPk, Sha256Digest>(), None);
    }

    #[test]
    fn encoded_bounds_include_the_exact_largest_decoded_ingress_group() {
        for (participants, chains, pipeline_depth, extension_bound) in
            [(1, 1, 1, 0), (6, 2, 3, 1), (11, 7, 64, 32)]
        {
            let codec = CodecConfig::new(
                participants,
                chains,
                PathLimits::new(pipeline_depth, extension_bound).unwrap(),
            )
            .unwrap();
            let sizes = ProtocolSizes::new::<MinPk, Sha256Digest>(codec).unwrap();
            let expected = sizes
                .max_artifact()
                .max(sizes.vqc.checked_add(sizes.signed_leader).unwrap());

            assert_eq!(
                codec
                    .encoded_bounds::<MinPk, Sha256Digest>()
                    .unwrap()
                    .max_ingress_group_bytes(),
                expected,
            );
        }
    }

    #[test]
    fn index_sums_follow_varint_widths() {
        assert_eq!(encoded_index_sum(0), Some(0));
        assert_eq!(encoded_index_sum(128), Some(128));
        assert_eq!(encoded_index_sum(129), Some(130));
        assert_eq!(largest_index_width_sum(129, 2), Some(3));
        assert_eq!(largest_index_width_sum(1, 2), None);
    }
}
