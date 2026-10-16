//! Scalar identifiers used by Multimmit.

use crate::{
    Heightable,
    types::{Attributable, Height, Participant},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
    util::at_least, varint::UInt,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::fmt::{self, Display, Formatter};

macro_rules! define_attributed_signature {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    /// Returns the zero-based chain index as a slice index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl_numeric_codec!(ChainId, u32);

/// The first entry of a per-chain sequence that does not name its own chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct MisplacedChain {
    /// Index of the entry in the sequence.
    pub(crate) index: usize,
    /// Chain the entry names.
    pub(crate) actual: ChainId,
}

/// Checks that the entry at index `i` names chain `i`.
pub(crate) fn ensure_canonical_chains(
    chains: impl IntoIterator<Item = ChainId>,
) -> Result<(), MisplacedChain> {
    for (index, actual) in chains.into_iter().enumerate() {
        if u32::try_from(index).map(ChainId::new) != Ok(actual) {
            return Err(MisplacedChain { index, actual });
        }
    }
    Ok(())
}

/// Returns the digest of `value`'s canonical encoding in the hash domain `namespace`.
pub(crate) fn canonical_digest<H: Hasher>(namespace: &[u8], value: &impl Encode) -> H::Digest {
    H::hash(&[namespace, value.encode().as_ref()])
}

/// A set of producer chains of one epoch, encoded as a bitmap over every chain.
///
/// The encoding is canonical: exactly `ceil(chains / 8)` bytes, chain `i` at bit `i % 8` of byte
/// `i / 8`, with every padding bit clear.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainSet {
    chains: u32,
    bits: Vec<u8>,
}

impl ChainSet {
    /// Returns the empty set over `chains` chains.
    pub fn empty(chains: usize) -> Self {
        let chains = u32::try_from(chains).expect("chain count fits u32");
        Self {
            chains,
            bits: vec![0; (chains as usize).div_ceil(8)],
        }
    }

    /// Returns the set of all `chains` chains.
    pub fn full(chains: usize) -> Self {
        let mut set = Self::empty(chains);
        for chain in 0..set.chains {
            set.insert(ChainId::new(chain));
        }
        set
    }

    /// Returns the set over `chains` chains holding `members`, or `None` if a member is out of
    /// range.
    pub fn from_chains(chains: usize, members: impl IntoIterator<Item = ChainId>) -> Option<Self> {
        let mut set = Self::empty(chains);
        for chain in members {
            if chain.get() >= set.chains {
                return None;
            }
            set.insert(chain);
        }
        Some(set)
    }

    /// Returns the number of chains the set ranges over.
    pub const fn chains(&self) -> usize {
        self.chains as usize
    }

    /// Returns whether `chain` is a member.
    pub fn contains(&self, chain: ChainId) -> bool {
        chain.get() < self.chains && self.bits[chain.index() / 8] & (1 << (chain.index() % 8)) != 0
    }

    /// Adds `chain` and returns whether it was absent.
    ///
    /// # Panics
    ///
    /// Panics if `chain` is outside the set's range.
    pub fn insert(&mut self, chain: ChainId) -> bool {
        assert!(chain.get() < self.chains, "chain outside the set's range");
        let absent = !self.contains(chain);
        self.bits[chain.index() / 8] |= 1 << (chain.index() % 8);
        absent
    }

    /// Returns the number of members.
    pub fn len(&self) -> usize {
        self.bits
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Returns whether the set has no members.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|byte| *byte == 0)
    }

    /// Returns whether every member of `self` is a member of `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.chains == other.chains
            && self
                .bits
                .iter()
                .zip(&other.bits)
                .all(|(mine, theirs)| mine & !theirs == 0)
    }

    /// Returns the chains in exactly one of `self` and `other`, or `None` if their ranges differ.
    pub fn symmetric_difference(&self, other: &Self) -> Option<Self> {
        (self.chains == other.chains).then(|| Self {
            chains: self.chains,
            bits: self
                .bits
                .iter()
                .zip(&other.bits)
                .map(|(mine, theirs)| mine ^ theirs)
                .collect(),
        })
    }

    /// Returns the members in ascending chain order.
    pub fn iter(&self) -> impl Iterator<Item = ChainId> + '_ {
        (0..self.chains)
            .map(ChainId::new)
            .filter(|chain| self.contains(*chain))
    }

    /// Returns the encoded size of a set over `chains` chains.
    pub(crate) const fn encoded_size(chains: usize) -> usize {
        chains.div_ceil(8)
    }
}

impl fmt::Debug for ChainSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

impl Write for ChainSet {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.bits);
    }
}

impl EncodeSize for ChainSet {
    fn encode_size(&self) -> usize {
        self.bits.len()
    }
}

impl Read for ChainSet {
    /// The number of chains the set ranges over.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &usize) -> Result<Self, Error> {
        let mut set = Self::empty(*chains);
        let len = set.bits.len();
        at_least(buf, len)?;
        buf.copy_to_slice(&mut set.bits);
        let used = *chains % 8;
        if used != 0 && set.bits[len - 1] >> used != 0 {
            return Err(Error::Invalid("ChainSet", "padding bits set"));
        }
        Ok(set)
    }
}

const CERTIFICATE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_CERTIFICATE";

/// Identifies a canonical certificate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CertificateId<D: Digest>(D);

impl<D: Digest> CertificateId<D> {
    /// Creates an identifier from its canonical digest.
    pub const fn new(digest: D) -> Self {
        Self(digest)
    }

    /// Creates the identifier of the certificate whose canonical encoding is `canonical`.
    pub fn from_canonical<H: Hasher<Digest = D>>(canonical: &[u8]) -> Self {
        Self(H::hash(&[CERTIFICATE_NAMESPACE, canonical]))
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
    use commonware_codec::{Copying, Decode, DecodeExt, Encode};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};

    #[test]
    fn numeric_codecs_round_trip_boundaries() {
        for value in [0, 1, 127, 128, u32::MAX] {
            let chain = ChainId::new(value);
            assert_eq!(ChainId::decode(chain.encode()).unwrap(), chain);
        }
    }

    #[test]
    fn canonical_chains_name_their_own_index() {
        assert_eq!(ensure_canonical_chains([]), Ok(()));
        assert_eq!(ensure_canonical_chains((0..3).map(ChainId::new)), Ok(()));
        assert_eq!(
            ensure_canonical_chains([0, 2, 1].map(ChainId::new)),
            Err(MisplacedChain {
                index: 1,
                actual: ChainId::new(2),
            })
        );
        assert_eq!(
            ensure_canonical_chains([ChainId::new(1)]),
            Err(MisplacedChain {
                index: 0,
                actual: ChainId::new(1),
            })
        );
    }

    #[test]
    fn canonical_digest_hashes_the_encoding_within_its_namespace() {
        let block = BlockRef::new(ChainId::new(7), Height::new(11), Sha256::hash(&[b"block"]));
        assert_eq!(
            canonical_digest::<Sha256>(b"domain", &block),
            Sha256::hash(&[b"domain".as_slice(), block.encode().as_ref()])
        );
        assert_ne!(
            canonical_digest::<Sha256>(b"domain", &block),
            canonical_digest::<Sha256>(b"other", &block)
        );
    }

    #[test]
    fn numeric_codecs_reject_non_canonical_varints() {
        assert!(ChainId::decode(Copying(&[0x80, 0x00])).is_err());
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

    #[test]
    fn chain_set_codec_is_canonical() {
        for chains in [1usize, 7, 8, 9, 17] {
            let set =
                ChainSet::from_chains(chains, (0..chains as u32).step_by(2).map(ChainId::new))
                    .unwrap();
            let encoded = set.encode();
            assert_eq!(encoded.len(), ChainSet::encoded_size(chains));
            assert_eq!(ChainSet::decode_cfg(encoded, &chains).unwrap(), set);
        }

        // Bit 3 of a five-chain set is in range; bit 5 is padding.
        assert!(ChainSet::decode_cfg(Copying(&[0b0000_1000]), &5).is_ok());
        assert!(ChainSet::decode_cfg(Copying(&[0b0010_0000]), &5).is_err());
        assert!(ChainSet::decode_cfg(Copying(&[0]), &9).is_err());
    }

    #[test]
    fn chain_set_operations() {
        let chains = 10;
        let low = ChainSet::from_chains(chains, [0, 3].map(ChainId::new)).unwrap();
        let high = ChainSet::from_chains(chains, [0, 3, 9].map(ChainId::new)).unwrap();
        assert!(low.is_subset(&high));
        assert!(!high.is_subset(&low));
        assert_eq!(high.len(), 3);
        assert_eq!(
            low.symmetric_difference(&high)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            vec![ChainId::new(9)]
        );
        assert!(low.symmetric_difference(&ChainSet::empty(9)).is_none());
        assert!(ChainSet::empty(chains).is_empty());
        assert_eq!(ChainSet::full(chains).len(), chains);
        assert!(ChainSet::from_chains(chains, [ChainId::new(10)]).is_none());
        assert!(!low.contains(ChainId::new(42)));
    }
}
