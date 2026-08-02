//! Scalar identifiers used by Multimmit.

use crate::{
    Heightable,
    types::{Attributable, Height, Participant},
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy, varint::UInt,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use core::{
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
};

macro_rules! define_attributed_signature {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name<V: Variant> {
            signer: Participant,
            signature: Lazy<V::Signature>,
        }

        impl<V: Variant> $name<V> {
            /// Creates an unverified attributed signature.
            pub const fn new(signer: Participant, signature: Lazy<V::Signature>) -> Self {
                Self { signer, signature }
            }

            /// Returns the decoded signature, or `None` if its group element is malformed.
            pub fn signature(&self) -> Option<&V::Signature> {
                self.signature.get()
            }

            /// Returns the encoded signature without decoding its group element.
            pub const fn lazy_signature(&self) -> &Lazy<V::Signature> {
                &self.signature
            }
        }

        impl<V: Variant> PartialEq for $name<V> {
            fn eq(&self, other: &Self) -> bool {
                self.signer == other.signer && self.signature == other.signature
            }
        }

        impl<V: Variant> Eq for $name<V> {}

        impl<V: Variant> Hash for $name<V> {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.signer.hash(state);
                self.signature.hash(state);
            }
        }

        impl<V: Variant> Attributable for $name<V> {
            fn signer(&self) -> Participant {
                self.signer
            }
        }

        impl<V: Variant> Write for $name<V> {
            fn write(&self, buf: &mut impl BufMut) {
                self.signer.write(buf);
                self.signature.write(buf);
            }
        }

        impl<V: Variant> Read for $name<V> {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
                Ok(Self::new(Participant::read(buf)?, Lazy::read(buf)?))
            }
        }

        impl<V: Variant> EncodeSize for $name<V> {
            fn encode_size(&self) -> usize {
                self.signer.encode_size() + self.signature.encode_size()
            }
        }
    };
}

define_attributed_signature!(
    Attestation,
    "An attributed ordinary BLS signature retained in aggregate transcripts."
);
define_attributed_signature!(
    ThresholdShare,
    "An attributed BLS threshold share used to recover an unattributed certificate."
);

macro_rules! impl_numeric_codec {
    ($type:ty, $integer:ty) => {
        impl Display for $type {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, formatter)
            }
        }

        impl Read for $type {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
                let value: $integer = UInt::read(buf)?.into();
                Ok(Self(value))
            }
        }

        impl Write for $type {
            fn write(&self, buf: &mut impl BufMut) {
                UInt(self.0).write(buf);
            }
        }

        impl EncodeSize for $type {
            fn encode_size(&self) -> usize {
                UInt(self.0).encode_size()
            }
        }
    };
}

/// Identifies one producer chain within an epoch.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChainId(u32);

impl ChainId {
    /// Creates a chain identifier from its zero-based index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Returns the zero-based chain index.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl_numeric_codec!(ChainId, u32);

/// Identifies a coordinate within one chain proposal.
///
/// Proposal-relative bounds are validated by the protocol object that carries
/// the position.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Position(u32);

impl Position {
    /// Creates a proposal coordinate.
    pub const fn new(position: u32) -> Self {
        Self(position)
    }

    /// Returns the underlying coordinate.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl_numeric_codec!(Position, u32);

/// Identifies a canonical certificate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CertificateId<D: Digest>(D);

impl<D: Digest> CertificateId<D> {
    /// Creates an identifier from its canonical digest.
    pub const fn new(digest: D) -> Self {
        Self(digest)
    }

    /// Returns the canonical digest.
    pub const fn get(self) -> D {
        self.0
    }
}

impl<D: Digest> Read for CertificateId<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(D::read(buf)?))
    }
}

impl<D: Digest> Write for CertificateId<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<D: Digest> FixedSize for CertificateId<D> {
    const SIZE: usize = D::SIZE;
}

/// Refers to one producer block without carrying its application body.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BlockRef<D: Digest> {
    chain: ChainId,
    height: Height,
    digest: D,
}

impl<D: Digest> BlockRef<D> {
    /// Creates a block reference.
    pub const fn new(chain: ChainId, height: Height, digest: D) -> Self {
        Self {
            chain,
            height,
            digest,
        }
    }

    /// Returns the block's producer chain.
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the block's chain-local height.
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the canonical producer-header digest.
    pub const fn digest(&self) -> D {
        self.digest
    }
}

impl<D: Digest> Heightable for BlockRef<D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest> Read for BlockRef<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            chain: ChainId::read(buf)?,
            height: Height::read(buf)?,
            digest: D::read(buf)?,
        })
    }
}

impl<D: Digest> Write for BlockRef<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.chain.write(buf);
        self.height.write(buf);
        self.digest.write(buf);
    }
}

impl<D: Digest> EncodeSize for BlockRef<D> {
    fn encode_size(&self) -> usize {
        self.chain.encode_size() + self.height.encode_size() + self.digest.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};

    #[test]
    fn numeric_codecs_round_trip_boundaries() {
        for value in [0, 1, 127, 128, u32::MAX] {
            let chain = ChainId::new(value);
            assert_eq!(ChainId::decode(chain.encode()).unwrap(), chain);

            let position = Position::new(value);
            assert_eq!(Position::decode(position.encode()).unwrap(), position);
        }
    }

    #[test]
    fn numeric_codecs_reject_non_canonical_varints() {
        assert!(ChainId::decode(&[0x80, 0x00][..]).is_err());
        assert!(Position::decode(&[0xff, 0x00][..]).is_err());
    }

    #[test]
    fn certificate_and_block_reference_round_trip() {
        let certificate = CertificateId::new(Sha256::hash(&[b"certificate"]));
        assert_eq!(
            CertificateId::decode(certificate.encode()).unwrap(),
            certificate
        );
        assert_eq!(
            certificate.encode_size(),
            <CertificateId<Sha256Digest> as FixedSize>::SIZE
        );

        let block = BlockRef::new(ChainId::new(7), Height::new(11), Sha256::hash(&[b"block"]));
        assert_eq!(BlockRef::decode(block.encode()).unwrap(), block);
        assert_eq!(block.chain(), ChainId::new(7));
        assert_eq!(block.height(), Height::new(11));
    }
}
