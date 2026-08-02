//! Peer-visible resolver keys for Multimmit marshal data.
//!
//! A key identifies only the object requested from a peer. Local resolver annotations and
//! subscriber state belong to the marshal actor and are deliberately not encoded here.

use crate::multimmit::types::{BlockRef, CertificateId, ChainId};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_utils::Span;
use core::fmt;

const LQC_BY_ID: u8 = 0;
const TIP_RECORD: u8 = 1;
const PRODUCER_BLOCK: u8 = 2;
const PRODUCER_HEADERS: u8 = 3;

/// Maximum number of compact ancestry records carried by one resolver value.
pub(in crate::multimmit::marshal) const MAX_SEGMENT_ITEMS: usize = 1024;

/// A peer-visible request for one Multimmit marshal object.
///
/// Exact objects are addressed by their canonical cryptographic identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Key<D: Digest> {
    /// Fetch an exact L-QC by its certificate identifier.
    LqcById {
        /// Canonical identifier of the L-QC.
        id: CertificateId<D>,
    },
    /// Fetch the authenticated tip-history opening for a commitment.
    TipRecord {
        /// Commitment of the tip-history record.
        commitment: D,
    },
    /// Fetch a complete producer block by its canonical header digest.
    ProducerBlock {
        /// Producer chain used to route the temporary-archive lookup.
        chain: ChainId,
        /// Canonical digest of the producer block header.
        digest: D,
    },
    /// Fetch a bounded producer-header segment beginning at an exact block reference.
    ProducerHeaders {
        /// Exact newest header requested by the consumer.
        head: BlockRef<D>,
    },
}

impl<D: Digest> Key<D> {
    /// Creates an exact L-QC lookup.
    pub const fn lqc_by_id(id: CertificateId<D>) -> Self {
        Self::LqcById { id }
    }

    /// Creates a tip-history opening lookup.
    pub const fn tip_record(commitment: D) -> Self {
        Self::TipRecord { commitment }
    }

    /// Creates a producer-block lookup by canonical header digest.
    pub const fn producer_block(chain: ChainId, digest: D) -> Self {
        Self::ProducerBlock { chain, digest }
    }

    /// Creates a bounded producer-header segment lookup.
    pub const fn producer_headers(head: BlockRef<D>) -> Self {
        Self::ProducerHeaders { head }
    }
}

impl<D: Digest> Write for Key<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::LqcById { id } => {
                LQC_BY_ID.write(buf);
                id.write(buf);
            }
            Self::TipRecord { commitment } => {
                TIP_RECORD.write(buf);
                commitment.write(buf);
            }
            Self::ProducerBlock { chain, digest } => {
                PRODUCER_BLOCK.write(buf);
                chain.write(buf);
                digest.write(buf);
            }
            Self::ProducerHeaders { head } => {
                PRODUCER_HEADERS.write(buf);
                head.write(buf);
            }
        }
    }
}

impl<D: Digest> EncodeSize for Key<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::LqcById { id } => id.encode_size(),
            Self::TipRecord { commitment } => commitment.encode_size(),
            Self::ProducerBlock { chain, digest } => chain.encode_size() + digest.encode_size(),
            Self::ProducerHeaders { head } => head.encode_size(),
        }
    }
}

impl<D: Digest> Read for Key<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            LQC_BY_ID => Ok(Self::lqc_by_id(CertificateId::read(buf)?)),
            TIP_RECORD => Ok(Self::tip_record(D::read(buf)?)),
            PRODUCER_BLOCK => Ok(Self::producer_block(ChainId::read(buf)?, D::read(buf)?)),
            PRODUCER_HEADERS => Ok(Self::producer_headers(BlockRef::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> Span for Key<D> {}

impl<D: Digest> fmt::Display for Key<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LqcById { id } => write!(formatter, "LqcById({id:?})"),
            Self::TipRecord { commitment } => write!(formatter, "TipRecord({commitment:?})"),
            Self::ProducerBlock { chain, digest } => {
                write!(formatter, "ProducerBlock({chain:?}, {digest:?})")
            }
            Self::ProducerHeaders { head } => write!(formatter, "ProducerHeaders({head:?})"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for Key<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3u8)? {
            LQC_BY_ID => Ok(Self::lqc_by_id(CertificateId::new(u.arbitrary()?))),
            1 => Ok(Self::tip_record(u.arbitrary()?)),
            2 => Ok(Self::producer_block(
                ChainId::new(u.arbitrary()?),
                u.arbitrary()?,
            )),
            3 => Ok(Self::producer_headers(u.arbitrary()?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    type D = Sha256Digest;

    fn digest(value: &'static [u8]) -> D {
        Sha256::hash(&[value])
    }

    #[test]
    fn round_trip_and_exact_sizes() {
        let keys = [
            Key::lqc_by_id(CertificateId::new(digest(b"lqc"))),
            Key::tip_record(digest(b"history")),
            Key::producer_block(ChainId::new(3), digest(b"block")),
            Key::producer_headers(BlockRef::new(
                ChainId::new(3),
                crate::types::Height::new(9),
                digest(b"headers"),
            )),
        ];

        for key in keys {
            let encoded = key.encode();
            assert_eq!(key.encode_size(), encoded.len());
            assert_eq!(Key::decode(encoded).unwrap(), key);
        }

        assert_eq!(keys[0].encode().len(), 1 + D::SIZE);
        assert_eq!(keys[1].encode().len(), 1 + D::SIZE);
        assert_eq!(
            keys[2].encode().len(),
            1 + ChainId::new(3).encode_size() + D::SIZE
        );
    }

    #[test]
    fn tags_are_canonical_and_invalid_tags_are_rejected() {
        let keys = [
            (
                LQC_BY_ID,
                Key::lqc_by_id(CertificateId::new(digest(b"lqc"))),
            ),
            (TIP_RECORD, Key::tip_record(digest(b"history"))),
            (
                PRODUCER_BLOCK,
                Key::producer_block(ChainId::new(3), digest(b"block")),
            ),
            (
                PRODUCER_HEADERS,
                Key::producer_headers(BlockRef::new(
                    ChainId::new(3),
                    crate::types::Height::new(9),
                    digest(b"headers"),
                )),
            ),
        ];

        for (tag, key) in keys {
            assert_eq!(key.encode()[0], tag);
        }

        assert!(matches!(
            Key::<D>::decode(&[4u8][..]),
            Err(commonware_codec::Error::InvalidEnum(4))
        ));
    }

    #[test]
    fn display_and_debug_include_the_peer_subject() {
        let key = Key::<D>::lqc_by_id(CertificateId::new(digest(b"lqc")));
        assert!(key.to_string().starts_with("LqcById("));
        assert!(format!("{key:?}").contains("LqcById"));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Key<D>> => 128,
        }
    }
}
