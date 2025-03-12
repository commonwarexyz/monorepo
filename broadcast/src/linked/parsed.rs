//! Parsed wrappers around wire types.

use crate::linked::{wire, Epoch};
use commonware_codec::{Codec, Error as CodecError, Reader, SizedCodec, Writer};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Signature as ThresholdSignature,
        poly::{PartialSignature, PARTIAL_SIGNATURE_LENGTH},
    },
    Scheme,
};
use commonware_utils::Array;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("Missing chunk")]
    MissingChunk,
    #[error("Missing parent")]
    ParentMissing,
    #[error("Parent on genesis chunk")]
    ParentOnGenesis,
    #[error("Invalid partial")]
    InvalidPartial,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Invalid sequencer")]
    InvalidSequencer,
    #[error("Invalid payload")]
    InvalidPayload,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Parsed version of a `Chunk`.
#[derive(Clone, Debug, Eq, PartialOrd, Ord, PartialEq)]
pub struct Chunk<D: Array, P: Array> {
    pub sequencer: P,
    pub height: u64,
    pub payload: D,
}

impl<D: Array, P: Array> Chunk<D, P> {
    /// Returns a `Chunk` from a `wire::Chunk`.
    pub fn from_wire(chunk: wire::Chunk) -> Result<Self, Error> {
        Ok(Self {
            sequencer: P::try_from(chunk.sequencer).map_err(|_| Error::InvalidSequencer)?,
            height: chunk.height,
            payload: D::try_from(chunk.payload).map_err(|_| Error::InvalidPayload)?,
        })
    }

    /// Returns a `wire::Chunk` from a `Chunk`.
    pub fn to_wire(&self) -> wire::Chunk {
        wire::Chunk {
            sequencer: self.sequencer.to_vec(),
            height: self.height,
            payload: self.payload.to_vec(),
        }
    }
}

impl<D: Array, P: Array> Codec for Chunk<D, P> {
    fn len_encoded(&self) -> usize {
        Self::LEN_CODEC
    }

    fn write(&self, writer: &mut impl Writer) {
        writer.write_fixed(&self.sequencer);
        writer.write(&self.height);
        writer.write_fixed(&self.payload);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        let sequencer = reader.read()?;
        let height = reader.read()?;
        let payload = reader.read()?;
        Ok(Self {
            sequencer,
            height,
            payload,
        })
    }
}

impl<D: Array, P: Array> SizedCodec for Chunk<D, P> {
    const LEN_CODEC: usize = P::SERIALIZED_LEN + 8 + D::SERIALIZED_LEN;
}

/// Parsed version of a `Parent`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parent<D: Array> {
    pub payload: D,
    pub epoch: Epoch,
    pub threshold: ThresholdSignature,
}

impl<D: Array> Codec for Parent<D> {
    fn len_encoded(&self) -> usize {
        Self::LEN_CODEC
    }

    fn write(&self, writer: &mut impl Writer) {
        writer.write_fixed(&self.payload);
        writer.write(&self.epoch);
        writer.write(&self.threshold);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        let payload = reader.read()?;
        let epoch = reader.read()?;
        let threshold = reader.read()?;
        Ok(Self {
            payload,
            epoch,
            threshold,
        })
    }
}

impl<D: Array> SizedCodec for Parent<D> {
    const LEN_CODEC: usize = D::SERIALIZED_LEN + Epoch::LEN_CODEC + ThresholdSignature::LEN_CODEC;
}

/// Parsed version of a `Node`.
#[derive(Clone, Eq)]
pub struct Node<C: Scheme, D: Array> {
    pub chunk: Chunk<D, C::PublicKey>,
    pub signature: C::Signature,
    pub parent: Option<Parent<D>>,
}

impl<C: Scheme, D: Array> Node<C, D> {
    /// Decode a `Node` from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let node = wire::Node::decode(bytes)?;
        let chunk = node.chunk.ok_or(Error::MissingChunk)?;
        let chunk = Chunk::from_wire(chunk)?;
        let parent = node.parent.map(Parent::from_wire).transpose()?;
        if chunk.height == 0 && parent.is_some() {
            return Err(Error::ParentOnGenesis);
        } else if chunk.height > 0 && parent.is_none() {
            return Err(Error::ParentMissing);
        }
        let signature =
            C::Signature::try_from(node.signature).map_err(|_| Error::InvalidSignature)?;
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }

    /// Encode a `Node` to bytes.
    pub fn encode(&self) -> Vec<u8> {
        wire::Node {
            chunk: Some(self.chunk.to_wire()),
            signature: self.signature.to_vec(),
            parent: self.parent.as_ref().map(|parent| parent.to_wire()),
        }
        .encode_to_vec()
    }
}

impl<C: Scheme, D: Array> Codec for Node<C, D> {
    fn len_encoded(&self) -> usize {
        Chunk::<D, C::PublicKey>::LEN_CODEC
            + self.signature.len_encoded()
            + self.parent.len_encoded()
    }

    fn write(&self, writer: &mut impl Writer) {
        writer.write(&self.chunk);
        writer.write(&self.signature);
        writer.write(&self.parent);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        let chunk = reader.read()?;
        let signature = reader.read()?;
        let parent = reader.read()?;
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }
}

impl<C: Scheme, D: Array> std::fmt::Debug for Node<C, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("chunk", &self.chunk)
            .field("signature", &self.signature)
            .field("parent", &self.parent)
            .finish()
    }
}

impl<C: Scheme, D: Array> PartialEq for Node<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk
            && self.signature == other.signature
            && self.parent == other.parent
    }
}

/// Parsed version of an `Ack`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ack<D: Array, P: Array> {
    pub chunk: Chunk<D, P>,
    pub epoch: Epoch,
    pub partial: PartialSignature,
}

impl<D: Array, P: Array> Codec for Ack<D, P> {
    fn len_encoded(&self) -> usize {
        Self::LEN_CODEC
    }

    fn encode(&self, writer: &mut impl Writer) {
        writer.write(&self.chunk);
        writer.write(&self.epoch);
        writer.write_fixed(&self.partial.serialize());
    }

    fn decode(reader: &mut impl Reader) -> Result<Self, CodecError> {
        let chunk = reader.read()?;
        let epoch = reader.read()?;
        let partial: [u8; PARTIAL_SIGNATURE_LENGTH] = reader.read_fixed()?;
        Ok(Self {
            chunk,
            epoch,
            partial: PartialSignature::deserialize(&partial).unwrap(),
        })
    }
}

impl<D: Array, P: Array> SizedCodec for Ack<D, P> {
    const LEN_CODEC: usize = Chunk::<D, P>::LEN_CODEC + 8 + PARTIAL_SIGNATURE_LENGTH;
}
