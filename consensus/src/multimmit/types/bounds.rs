//! Encoded-size maxima of bounded protocol objects under one [`CodecConfig`].
//!
//! Each protocol object states its largest encoding beside its `Write` impl as
//! `max_encode_size`. This module holds the varint arithmetic those bounds share and composes them
//! into [`EncodedBounds`]: the artifact, ingress-group, and network-frame ceilings enforced before
//! decoding. All arithmetic is checked, and `None` means the epoch's shape does not fit the wire
//! format on this target.

use super::{CodecConfig, Lqc, SignedLeaderBlock, SignedTransactionBlock, VoteUpdate, Vqc};
use commonware_codec::{EncodeSize as _, FixedSize as _, varint::UInt};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::num::NonZeroUsize;

/// Largest encoding of a `u64` varint.
pub(super) const MAX_U64_VARINT_SIZE: usize = 10;

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
    /// The largest artifact is usually the V-QC, bounded by [`CodecConfig::max_vqc_bytes`]; a
    /// deployment's artifact byte limit must cover this value.
    pub fn max_artifact_bytes<V: Variant, D: Digest>(self) -> Option<NonZeroUsize> {
        NonZeroUsize::new(self.encoded_bounds::<V, D>()?.max_artifact_bytes())
    }

    /// Computes encoded upper bounds for this epoch's bounded protocol objects.
    pub(crate) fn encoded_bounds<V: Variant, D: Digest>(self) -> Option<EncodedBounds> {
        let sizes = ProtocolSizes::new::<V, D>(self)?;
        let envelope = checked_sum(&[1, MAX_U64_VARINT_SIZE])?;

        let max_artifact_bytes = sizes.max_artifact();
        // A proposal carries its leader block and optionally the parent V-QC.
        let proposal_group = checked_sum(&[sizes.vqc, sizes.signed_leader])?;
        let max_ingress_group_bytes = max_artifact_bytes.max(proposal_group);
        let max_data_frame_bytes = checked_sum(&[envelope, 1, sizes.signed_transaction])?;
        let proposal = checked_sum(&[1, proposal_group])?;
        let max_consensus_frame_bytes = checked_sum(&[envelope, 1, proposal.max(sizes.update)])?;
        let max_certificate_frame_bytes = checked_sum(&[envelope, 1, sizes.vqc.max(sizes.lqc)])?;

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
    signed_leader: usize,
    update: usize,
    vqc: usize,
    lqc: usize,
    /// An L-QC with the record opening its leader block's history commitment.
    floor: usize,
}

impl ProtocolSizes {
    fn new<V: Variant, D: Digest>(codec: CodecConfig) -> Option<Self> {
        Some(Self {
            signed_transaction: SignedTransactionBlock::<V, D>::max_encode_size(codec)?,
            signed_leader: SignedLeaderBlock::<V, D>::max_encode_size(codec)?,
            update: VoteUpdate::<V, D>::max_encode_size(codec)?,
            vqc: Vqc::<V, D>::max_encode_size(codec),
            lqc: Lqc::<V, D>::max_encode_size(codec)?,
            floor: checked_sum(&[
                Lqc::<V, D>::max_encode_size(codec)?,
                D::SIZE,
                encoded_vec(codec.chains(), block_ref_size::<D>(codec)?)?,
            ])?,
        })
    }

    fn max_artifact(&self) -> usize {
        [
            self.signed_transaction,
            self.signed_leader,
            self.update,
            self.vqc,
            self.lqc,
            self.floor,
        ]
        .into_iter()
        .max()
        .expect("artifact set is non-empty")
    }
}

/// Returns the largest encoding of a block reference under `codec`.
pub(super) fn block_ref_size<D: Digest>(codec: CodecConfig) -> Option<usize> {
    checked_sum(&[
        max_index_width(codec.chains())?,
        MAX_U64_VARINT_SIZE,
        D::SIZE,
    ])
}

/// Returns the sum of `values`.
pub(super) fn checked_sum(values: &[usize]) -> Option<usize> {
    values
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(*value))
}

/// Returns the encoded size of a length or index `value`, which the wire format caps at `u32`.
pub(super) fn encoded_len(value: usize) -> Option<usize> {
    let value = u32::try_from(value).ok()?;
    Some(UInt(value).encode_size())
}

/// Returns the encoded size of `count` items of `item_size` bytes behind a length prefix.
pub(super) fn encoded_vec(count: usize, item_size: usize) -> Option<usize> {
    checked_sum(&[encoded_len(count)?, count.checked_mul(item_size)?])
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{
            Attestation, BlockRef, CertificateId, ChainChange, ChainSet, Endorsement, LeaderBlock,
            VoteContent, VoteTally, Window,
        },
        types::{Epoch, Height, Participant, Round, View},
    };
    use commonware_codec::{Encode as _, types::lazy::Lazy};
    use commonware_cryptography::{
        Hasher as _, Sha256,
        bls12381::primitives::{
            ops::aggregate,
            variant::{MinPk, MinSig},
        },
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Additive as _;

    type D = Sha256Digest;

    fn maximal_tips(codec: CodecConfig, salt: u8) -> Vec<BlockRef<D>> {
        codec
            .chain_ids()
            .map(|chain| BlockRef::new(chain, Height::new(u64::MAX), Sha256::hash(&[&[salt]])))
            .collect()
    }

    fn assert_maximal_objects_fit<V: Variant>() {
        for (participants, chains) in [(1, 1), (6, 6), (11, 3), (16, 129), (130, 2)] {
            let codec = CodecConfig::new(participants, chains, Window::new(16).unwrap()).unwrap();
            let round = Round::new(Epoch::new(u64::MAX), View::new(u64::MAX));
            let leader = Sha256::hash(&[b"leader"]);
            let signer = Participant::from_usize(participants - 1);
            let attestation = Attestation::<V>::new(signer, Lazy::from(V::Signature::zero()));

            let changes = codec
                .chain_ids()
                .map(|chain| {
                    ChainChange::new(
                        BlockRef::new(chain, Height::new(u64::MAX), leader),
                        vec![leader; codec.window().delta_max() as usize],
                        codec,
                    )
                    .unwrap()
                })
                .collect();
            let update = VoteUpdate::new(
                round,
                Some(leader),
                true,
                ChainSet::full(chains),
                u32::MAX,
                changes,
                attestation,
                codec,
            )
            .unwrap();
            assert!(update.encode_size() <= VoteUpdate::<V, D>::max_encode_size(codec).unwrap());

            // Every signer but the reference deviates in every field and on every chain.
            let quorum = codec.view_quorum();
            let contents = (0..quorum).map(|index| {
                let declared = if index == 0 {
                    ChainSet::empty(chains)
                } else {
                    ChainSet::full(chains)
                };
                let endorsement =
                    Endorsement::new(declared, maximal_tips(codec, index as u8), codec).unwrap();
                let content =
                    VoteContent::new(round, Some(leader), index % 2 == 0, endorsement).unwrap();
                (
                    Participant::from_usize(participants - quorum + index),
                    content,
                )
            });
            let tally = VoteTally::from_contents(leader, contents, codec).unwrap();
            let lqc = Lqc::<V, D>::new(
                LeaderBlock::new(round, CertificateId::new(leader), leader).unwrap(),
                tally,
                aggregate::Signature::<V>::zero(),
            );
            assert!(lqc.encode().len() <= Lqc::<V, D>::max_encode_size(codec).unwrap());

            let bounds = codec.encoded_bounds::<V, D>().unwrap();
            assert!(bounds.max_artifact_bytes() >= codec.max_vqc_bytes());
            assert!(bounds.max_certificate_frame_bytes() > lqc.encode_size());
            assert!(bounds.max_consensus_frame_bytes() > update.encode_size());
        }
    }

    #[test]
    fn encoded_bounds_cover_maximal_objects() {
        assert_maximal_objects_fit::<MinPk>();
        assert_maximal_objects_fit::<MinSig>();
    }

    #[test]
    fn checked_encoded_bounds_reject_overflow_without_allocating() {
        assert_eq!(checked_sum(&[usize::MAX, 1]), None);
        assert_eq!(encoded_vec(usize::MAX, 2), None);
        assert_eq!(encoded_len(u32::MAX as usize + 1), None);
    }
}
