use super::block::BlockFormat;
use crate::Scheme;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::Digest;

/// Enum representing responses from the indexer to validators.
///
/// These responses correspond to the results of the operations requested by `Inbound` messages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Outbound<D: Digest> {
    /// Indicates the success or failure of a `Put` operation,
    /// or if a `Get` operation found the requested item.
    Success(bool),
    /// Contains the requested block data in response to a `GetBlock` message.
    Block(BlockFormat<D>),
    /// Contains the requested finality certificate in response to a `GetFinalization` message.
    Finalization(Finalization<Scheme, D>),
}

impl<D: Digest> Write for Outbound<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Success(success) => {
                buf.put_u8(0);
                success.write(buf);
            }
            Self::Block(data) => {
                buf.put_u8(1);
                data.write(buf);
            }
            Self::Finalization(data) => {
                buf.put_u8(2);
                data.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for Outbound<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => {
                let success = bool::read(buf)?;
                Ok(Self::Success(success))
            }
            1 => {
                let block = BlockFormat::<D>::read(buf)?;
                Ok(Self::Block(block))
            }
            2 => {
                let finalization = Finalization::read(buf)?;
                Ok(Self::Finalization(finalization))
            }
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for Outbound<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Success(success) => success.encode_size(),
            Self::Block(data) => data.encode_size(),
            Self::Finalization(finalization) => finalization.encode_size(),
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
            group::{self, Element},
            variant::{MinSig, Variant},
        },
        sha256::Digest as Sha256Digest,
    };
    use rand::thread_rng;

    fn new_block() -> BlockFormat<Sha256Digest> {
        BlockFormat::Random(12345678901234567890)
    }

    fn new_digest() -> Sha256Digest {
        Sha256Digest::decode(&[123u8; Sha256Digest::SIZE][..]).unwrap()
    }

    fn new_finalization() -> Finalization<Scheme, Sha256Digest> {
        let scalar = group::Scalar::from_rand(&mut thread_rng());
        let mut proposal_signature = <MinSig as Variant>::Signature::one();
        proposal_signature.mul(&scalar);
        let mut seed_signature = <MinSig as Variant>::Signature::one();
        seed_signature.mul(&scalar);
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
