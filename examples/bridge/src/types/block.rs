use crate::Scheme;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::Digest;

/// Enum representing the valid formats for blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BlockFormat<D: Digest> {
    /// A random set of arbitrary data.
    Random(u128),

    /// A finalization certificate of a block from a different network.
    Bridge(Finalization<Scheme, D>),
}

impl<D: Digest> Write for BlockFormat<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Random(random) => {
                0u8.write(buf);
                random.write(buf);
            }
            Self::Bridge(finalization) => {
                1u8.write(buf);
                finalization.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for BlockFormat<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => {
                let random = u128::read(buf)?;
                Ok(Self::Random(random))
            }
            1 => {
                let finalization = Finalization::read(buf)?;
                Ok(Self::Bridge(finalization))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for BlockFormat<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Random(random) => random.encode_size(),
            Self::Bridge(finalization) => finalization.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_consensus::{
        simplex::{signing_scheme::bls12381_threshold, types::Proposal},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::{
            group::{self},
            variant::{MinSig, Variant},
        },
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::{CryptoGroup, Random as _};
    use rand::thread_rng;

    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_finalization() -> Finalization<Scheme, Sha256Digest> {
        let scalar = group::Scalar::random(&mut thread_rng());
        let mut proposal_signature = <MinSig as Variant>::Signature::generator();
        proposal_signature *= &scalar;
        let mut seed_signature = <MinSig as Variant>::Signature::generator();
        seed_signature *= &scalar;
        Finalization {
            proposal: Proposal {
                round: Round::new(Epoch::new(333), View::new(12345)),
                parent: View::new(54321),
                payload: new_digest(),
            },
            certificate: bls12381_threshold::Signature::<MinSig> {
                vote_signature: proposal_signature,
                seed_signature,
            },
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
