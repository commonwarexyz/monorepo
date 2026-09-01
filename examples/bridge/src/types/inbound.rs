use super::block::BlockFormat;
use crate::Scheme;
use commonware_codec::{EncodeSize, FixedSize, Read, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::{
    Digest,
    bls12381::primitives::variant::{MinSig, Variant},
};

/// Enum representing incoming messages from validators to the indexer.
///
/// Used to interact with the indexer's storage of blocks and finality certificates.
#[derive(Debug, Clone, PartialEq, Eq, EncodeSize, Read, Write)]
#[allow(clippy::large_enum_variant)]
pub enum Inbound<D: Digest> {
    /// Request to store a new block in the indexer's storage.
    #[codec(tag = 0)]
    PutBlock(PutBlock<D>),
    /// Request to retrieve a block from the indexer's storage.
    #[codec(tag = 1)]
    GetBlock(GetBlock<D>),
    /// Request to store a finality certificate in the indexer's storage.
    #[codec(tag = 2)]
    PutFinalization(PutFinalization<D>),
    /// Request to retrieve the latest finality certificate from the indexer's storage.
    #[codec(tag = 3)]
    GetFinalization(GetFinalization),
}

/// Message to store a new block in the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq, EncodeSize, Read, Write)]
pub struct PutBlock<D: Digest> {
    /// The network identifier for which the block belongs.
    pub network: <MinSig as Variant>::Public,
    /// The block to be stored.
    pub block: BlockFormat<D>,
}

/// Message to retrieve a block from the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq, FixedSize, Read, Write)]
pub struct GetBlock<D: Digest> {
    /// The network identifier for which the block belongs.
    pub network: <MinSig as Variant>::Public,
    /// The digest of the block to retrieve.
    pub digest: D,
}

/// Message to store a finality certificate in the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq, EncodeSize, Read, Write)]
pub struct PutFinalization<D: Digest> {
    /// The network identifier for which the finality certificate belongs.
    pub network: <MinSig as Variant>::Public,
    /// The finality certificate
    pub finalization: Finalization<Scheme, D>,
}

/// Message to retrieve the latest finality certificate from the indexer's storage.
#[derive(Debug, Clone, PartialEq, Eq, EncodeSize, Read, Write)]
pub struct GetFinalization {
    /// The network identifier for which to retrieve the finality certificate.
    pub network: <MinSig as Variant>::Public,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_consensus::{
        simplex::types::Proposal,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::{certificate::threshold::Certificate, primitives::group},
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

    fn new_group_public() -> <MinSig as Variant>::Public {
        let mut result = <MinSig as Variant>::Public::generator();
        let scalar = group::Scalar::random(test_rng());
        result *= &scalar;
        result
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
    fn test_inbound_codec() {
        // PutBlock
        let original = Inbound::<Sha256Digest>::PutBlock(PutBlock {
            network: new_group_public(),
            block: new_block(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // GetBlock
        let original = Inbound::<Sha256Digest>::GetBlock(GetBlock {
            network: new_group_public(),
            digest: new_digest(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // PutFinalization
        let original = Inbound::<Sha256Digest>::PutFinalization(PutFinalization {
            network: new_group_public(),
            finalization: new_finalization(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);

        // GetFinalization
        let original = Inbound::<Sha256Digest>::GetFinalization(GetFinalization {
            network: new_group_public(),
        });
        let encoded = original.encode();
        let decoded = Inbound::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
