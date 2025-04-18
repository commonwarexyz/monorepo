use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::threshold_simplex::types::Finalization;
use commonware_cryptography::Digest;

/// Enum representing the valid formats for blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BlockFormat<D: Digest> {
    /// A random set of arbitrary data.
    Random(u128),

    /// A finalization certificate of a block from a different network.
    Bridge(Finalization<D>),
}

impl<D: Digest> Write for BlockFormat<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            BlockFormat::Random(random) => {
                0u8.write(buf);
                random.write(buf);
            }
            BlockFormat::Bridge(finalization) => {
                1u8.write(buf);
                finalization.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for BlockFormat<D> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => {
                let random = u128::read(buf)?;
                Ok(BlockFormat::Random(random))
            }
            1 => {
                let finalization = Finalization::read(buf)?;
                Ok(BlockFormat::Bridge(finalization))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for BlockFormat<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            BlockFormat::Random(random) => random.encode_size(),
            BlockFormat::Bridge(finalization) => finalization.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_consensus::threshold_simplex::types::Proposal;
    use commonware_cryptography::{
        bls12381::primitives::group::{self, Element, G2},
        sha256::Digest as Sha256Digest,
    };
    use rand::thread_rng;

    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_finalization() -> Finalization<Sha256Digest> {
        let scalar = group::Scalar::rand(&mut thread_rng());
        let mut proposal_signature = G2::one();
        proposal_signature.mul(&scalar);
        let mut seed_signature = G2::one();
        seed_signature.mul(&scalar);
        Finalization {
            proposal: Proposal {
                view: 12345,
                parent: 54321,
                payload: new_digest(),
            },
            proposal_signature,
            seed_signature,
        }
    }

    #[test]
    fn test_block_codec() {
        // Random
        let original = BlockFormat::<Sha256Digest>::Random(12345678901234567890);
        let encoded = original.encode();
        let decoded = BlockFormat::<Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // Bridge
        let original = BlockFormat::<Sha256Digest>::Bridge(new_finalization());
        let encoded = original.encode();
        let decoded = BlockFormat::<Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // Invalid tag
        let buf = [2u8];
        let result = BlockFormat::<Sha256Digest>::decode(&buf[..]);
        assert!(matches!(result, Err(Error::InvalidEnum(2))));
    }
}
