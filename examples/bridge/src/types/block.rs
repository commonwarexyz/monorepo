use crate::Scheme;
use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::Digest;

/// Enum representing the valid formats for blocks.
#[derive(Debug, Clone, PartialEq, Eq, EncodeSize, Read, Write)]
#[allow(clippy::large_enum_variant)]
pub enum BlockFormat<D: Digest> {
    /// A random set of arbitrary data.
    #[codec(tag = 0)]
    Random(u128),

    /// A finalization certificate of a block from a different network.
    #[codec(tag = 1)]
    Bridge(Finalization<Scheme, D>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, Error, FixedSize};
    use commonware_consensus::{
        simplex::types::Proposal,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::{
            certificate::threshold::Certificate,
            primitives::{
                group,
                variant::{MinSig, Variant},
            },
        },
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::{CryptoGroup, Random as _};
    use commonware_utils::test_rng;

    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_finalization() -> Finalization<Scheme, Sha256Digest> {
        let scalar = group::Scalar::random(test_rng());
        let mut signature = <MinSig as Variant>::Signature::generator();
        signature *= &scalar;
        Finalization {
            proposal: Proposal {
                round: Round::new(Epoch::new(333), View::new(12345)),
                parent: View::new(54321),
                payload: new_digest(),
            },
            certificate: Certificate::new(signature),
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
