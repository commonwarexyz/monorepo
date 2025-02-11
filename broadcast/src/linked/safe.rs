use super::{wire, Epoch};
use bytes::Bytes;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Signature as ThresholdSignature},
        poly::PartialSignature,
    },
    Array, Scheme,
};
use prost::Message;

/// Safe version of a `Chunk`.
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
            sequencer: P::try_from(chunk.sequencer).map_err(|_| Error::InvalidPublicKey)?,
            height: chunk.height,
            payload: D::try_from(chunk.payload).map_err(|_| Error::InvalidDigest)?,
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

/// Safe version of a `Parent`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parent<D: Array> {
    pub payload: D,
    pub epoch: Epoch,
    pub threshold: ThresholdSignature,
}

impl<D: Array> Parent<D> {
    /// Returns a `Parent` from a `wire::Parent`.
    pub fn from_wire(parent: wire::Parent) -> Result<Self, Error> {
        Ok(Self {
            payload: D::try_from(parent.payload).map_err(|_| Error::InvalidDigest)?,
            epoch: parent.epoch,
            threshold: ThresholdSignature::deserialize(&parent.threshold)
                .ok_or(Error::InvalidThreshold)?,
        })
    }

    /// Returns a `wire::Parent` from a `Parent`.
    pub fn to_wire(&self) -> wire::Parent {
        wire::Parent {
            payload: self.payload.to_vec(),
            epoch: self.epoch,
            threshold: self.threshold.serialize(),
        }
    }
}

/// Safe version of a `Link`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link<C: Scheme, D: Array> {
    pub chunk: Chunk<D, C::PublicKey>,
    pub signature: C::Signature,
    pub parent: Option<Parent<D>>,
}

impl<C: Scheme, D: Array> Link<C, D> {
    /// Decode a `Link` from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let link = wire::Link::decode(bytes)?;
        let chunk = link.chunk.ok_or(Error::MissingChunk)?;
        let chunk = Chunk::from_wire(chunk)?;
        let parent = link.parent.map(Parent::from_wire).transpose()?;
        if chunk.height == 0 && parent.is_some() {
            return Err(Error::ParentOnGenesis);
        } else if chunk.height > 0 && parent.is_none() {
            return Err(Error::ParentMissing);
        }
        let signature =
            C::Signature::try_from(link.signature).map_err(|_| Error::InvalidSignature)?;
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }

    /// Encode a `Link` to bytes.
    pub fn encode(&self) -> Result<Bytes, Error> {
        let link = wire::Link {
            chunk: Some(Chunk::to_wire(&self.chunk)),
            signature: self.signature.to_vec(),
            parent: self.parent.as_ref().map(|parent| wire::Parent {
                payload: parent.payload.to_vec(),
                epoch: parent.epoch,
                threshold: parent.threshold.serialize(),
            }),
        };

        let mut buf = Vec::new();
        link.encode(&mut buf)?;

        Ok(buf.into())
    }
}

/// Safe version of an `Ack`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ack<D: Array, P: Array> {
    pub chunk: Chunk<D, P>,
    pub epoch: Epoch,
    pub partial: PartialSignature,
}

impl<D: Array, P: Array> Ack<D, P> {
    /// Decode an `Ack` from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let ack = wire::Ack::decode(bytes).map_err(Error::Decode)?;
        let chunk = ack.chunk.ok_or(Error::MissingChunk)?;

        Ok(Self {
            chunk: Chunk::from_wire(chunk)?,
            epoch: ack.epoch,
            partial: PartialSignature::deserialize(ack.partial.as_ref())
                .ok_or(Error::InvalidPartial)?,
        })
    }

    /// Encode an `Ack` to bytes.
    pub fn encode(&self) -> Result<Bytes, Error> {
        let ack = wire::Ack {
            chunk: Some(Chunk::to_wire(&self.chunk)),
            epoch: self.epoch,
            partial: self.partial.serialize(),
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).map_err(Error::Encode)?;
        Ok(buf.into())
    }
}

// Errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("Encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("Missing chunk")]
    MissingChunk,
    #[error("Missing parent")]
    ParentMissing,
    #[error("Parent on genesis chunk")]
    ParentOnGenesis,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid digest")]
    InvalidDigest,
    #[error("Invalid partial")]
    InvalidPartial,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Invalid signature")]
    InvalidSignature,
}
