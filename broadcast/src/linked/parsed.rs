use crate::linked::{wire, Epoch};
use commonware_cryptography::Array;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, Signature as ThresholdSignature},
        poly::PartialSignature,
    },
    Scheme,
};
use prost::Message;

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
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] commonware_cryptography::Error),
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
            sequencer: P::try_from(chunk.sequencer).map_err(Error::Crypto)?,
            height: chunk.height,
            payload: D::try_from(chunk.payload).map_err(Error::Crypto)?,
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

/// Parsed version of a `Parent`.
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
            payload: D::try_from(parent.payload).map_err(Error::Crypto)?,
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

/// Parsed version of a `Link`.
#[derive(Clone, Eq)]
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
        let signature = C::Signature::try_from(link.signature).map_err(Error::Crypto)?;
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }

    /// Encode a `Link` to bytes.
    pub fn encode(&self) -> Vec<u8> {
        wire::Link {
            chunk: Some(self.chunk.to_wire()),
            signature: self.signature.to_vec(),
            parent: self.parent.as_ref().map(|parent| parent.to_wire()),
        }
        .encode_to_vec()
    }
}

impl<C: Scheme, D: Array> std::fmt::Debug for Link<C, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("chunk", &self.chunk)
            .field("signature", &self.signature)
            .field("parent", &self.parent)
            .finish()
    }
}

impl<C: Scheme, D: Array> PartialEq for Link<C, D> {
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
    pub fn encode(&self) -> Vec<u8> {
        wire::Ack {
            chunk: Some(Chunk::to_wire(&self.chunk)),
            epoch: self.epoch,
            partial: self.partial.serialize(),
        }
        .encode_to_vec()
    }
}
