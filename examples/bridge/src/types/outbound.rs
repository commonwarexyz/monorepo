use super::block::BlockFormat;
use crate::Scheme;
use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::Digest;

/// Enum representing responses from the indexer to validators.
///
/// These responses correspond to the results of the operations requested by `Inbound` messages.
#[derive(Debug, Clone, PartialEq, Eq, EncodeSize, Read, Write)]
#[allow(clippy::large_enum_variant)]
pub enum Outbound<D: Digest> {
    /// Indicates the success or failure of a `Put` operation,
    /// or if a `Get` operation found the requested item.
    #[codec(tag = 0)]
    Success(bool),
    /// Contains the requested block data in response to a `GetBlock` message.
    #[codec(tag = 1)]
    Block(BlockFormat<D>),
    /// Contains the requested finality certificate in response to a `GetFinalization` message.
    #[codec(tag = 2)]
    Finalization(Finalization<Scheme, D>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode, FixedSize};
    use commonware_consensus::{
        simplex::types::Proposal,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::{
            certificate::threshold::Certificate,
            primitives::{group, variant::MinSig},
        },
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::{CryptoGroup, Random as _};
    use commonware_utils::test_rng;

    fn new_block() -> BlockFormat<Sha256Digest> {
        BlockFormat::Random(12345678901234567890)
    }

    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_finalization() -> Finalization<Scheme, Sha256Digest> {
        let scalar = group::Scalar::random(test_rng());
        let mut signature = <MinSig as commonware_cryptography::bls12381::primitives::variant::Variant>::Signature::generator();
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
    fn test_outbound_codec() {
        // Success
        let original = Outbound::<Sha256Digest>::Success(true);
        let encoded = original.encode();
        let decoded = Outbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // Block
        let original = Outbound::<Sha256Digest>::Block(new_block());
        let encoded = original.encode();
        let decoded = Outbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // Finalization
        let original = Outbound::<Sha256Digest>::Finalization(new_finalization());
        let encoded = original.encode();
        let decoded = Outbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
