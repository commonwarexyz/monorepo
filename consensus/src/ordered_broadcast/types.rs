use super::Error;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Public, Signature},
        ops,
        poly::{self, PartialSignature},
    },
    Digest, Verifier,
};
use commonware_utils::{union, Array};

/// Used as the [`Index`](crate::Supervisor::Index) type.
/// Defines the current set of sequencers and validators.
///
/// This is not a single "View" in the sense of a consensus protocol, but rather a continuous
/// sequence of views in-which the set of sequencers and validators is constant.
pub type Epoch = u64;

/// Used as the [`Automaton::Context`](crate::Automaton::Context) type.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context<P: Array> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: u64,
}

const CHUNK_SUFFIX: &[u8] = b"_CHUNK";
const ACK_SUFFIX: &[u8] = b"_ACK";

/// Returns a suffixed namespace for signing a chunk.
pub fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

/// Returns a suffixed namespace for signing an ack.
pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

/// Chunk is a message generated by a sequencer that is broadcasted to all validators.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Chunk<P: Array, D: Digest> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: u64,

    /// Digest of the payload.
    pub payload: D,
}

impl<P: Array, D: Digest> Chunk<P, D> {
    /// Create a new chunk with the given sequencer, height, and payload.
    pub fn new(sequencer: P, height: u64, payload: D) -> Self {
        Self {
            sequencer,
            height,
            payload,
        }
    }
}

impl<P: Array, D: Digest> Write for Chunk<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.sequencer.write(writer);
        self.height.write(writer);
        self.payload.write(writer);
    }
}

impl<P: Array, D: Digest> Read for Chunk<P, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let sequencer = P::read(reader)?;
        let height = u64::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Self {
            sequencer,
            height,
            payload,
        })
    }
}

impl<P: Array, D: Digest> FixedSize for Chunk<P, D> {
    const SIZE: usize = P::SIZE + u64::SIZE + D::SIZE;
}

/// Parent is a message that contains information about the parent (previous height) of a Chunk.
///
/// The sequencer and height are not provided as they are implied by the sequencer and height of the current chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Parent<D: Digest> {
    /// Digest of the parent chunk.
    pub digest: D,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Signature over the parent.
    pub signature: Signature,
}

impl<D: Digest> Parent<D> {
    /// Create a new parent with the given digest, epoch, and signature.
    pub fn new(digest: D, epoch: Epoch, signature: Signature) -> Self {
        Self {
            digest,
            epoch,
            signature,
        }
    }
}

impl<D: Digest> Write for Parent<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.digest.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<D: Digest> Read for Parent<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let digest = D::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = Signature::read(reader)?;
        Ok(Self {
            digest,
            epoch,
            signature,
        })
    }
}

impl<D: Digest> FixedSize for Parent<D> {
    const SIZE: usize = D::SIZE + Epoch::SIZE + Signature::SIZE;
}

/// Node is a message from a sequencer that contains a Chunk and a proof that the parent was correctly broadcasted.
///
/// It represents a newly-proposed tip of the chain for the given sequencer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Node<C: Verifier, D: Digest> {
    /// Chunk of the node.
    pub chunk: Chunk<C::PublicKey, D>,

    /// Signature of the sequencer the chunk.
    pub signature: C::Signature,

    /// Information about the parent chunk
    ///
    /// This part is not signed over, but it is used to verify that the previous chunk in the chain was correctly broadcast.
    pub parent: Option<Parent<D>>,
}

impl<C: Verifier, D: Digest> Node<C, D> {
    /// Create a new node with the given chunk, signature, and parent.
    pub fn new(
        chunk: Chunk<C::PublicKey, D>,
        signature: C::Signature,
        parent: Option<Parent<D>>,
    ) -> Self {
        Self {
            chunk,
            signature,
            parent,
        }
    }

    pub fn verify(&self, public: &Public, chunk_namespace: &[u8], ack_namespace: &[u8]) -> bool {
        // Verify chunk
        let message = self.chunk.encode();
        if !C::verify(
            Some(chunk_namespace),
            &message,
            &self.chunk.sequencer,
            &self.signature,
        ) {
            return false;
        }
        let Some(parent) = &self.parent else {
            return true;
        };

        // Verify parent (if present)
        let parent_chunk = Chunk::new(
            self.chunk.sequencer.clone(),
            self.chunk.height - 1, // Will not parse if height is 0 and parent exists
            parent.digest.clone(),
        );
        verify_lock(
            public,
            &parent_chunk,
            &parent.epoch,
            &parent.signature,
            ack_namespace,
        )
    }
}

impl<C: Verifier, D: Digest> Write for Node<C, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
        if let Some(parent) = &self.parent {
            true.write(writer);
            parent.write(writer);
        } else {
            false.write(writer);
        }
    }
}

impl<C: Verifier, D: Digest> Read for Node<C, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = C::Signature::read(reader)?;
        let parent = if bool::read(reader)? {
            Some(Parent::read(reader)?)
        } else {
            None
        };
        if chunk.height == 0 && parent.is_some() {
            return Err(CodecError::Wrapped(
                "consensus::ordered_broadcast::Node",
                Box::new(Error::ParentOnGenesis),
            ));
        } else if chunk.height > 0 && parent.is_none() {
            return Err(CodecError::Wrapped(
                "consensus::ordered_broadcast::Node",
                Box::new(Error::ParentMissing),
            ));
        }
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }
}

impl<C: Verifier, D: Digest> EncodeSize for Node<C, D> {
    fn encode_size(&self) -> usize {
        let parent_size = if self.parent.is_some() {
            Parent::<D>::SIZE
        } else {
            0
        };
        Chunk::<C::PublicKey, D>::SIZE + D::SIZE + bool::SIZE + parent_size
    }
}

/// Ack is a message sent by a validator to acknowledge the receipt of a Chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<P: Array, D: Digest> {
    /// Chunk that is being acknowledged.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Partial signature over the chunk.
    pub signature: PartialSignature,
}

impl<P: Array, D: Digest> Ack<P, D> {
    /// Create a new ack with the given chunk, epoch, and signature.
    pub fn new(chunk: Chunk<P, D>, epoch: Epoch, signature: PartialSignature) -> Self {
        Self {
            chunk,
            epoch,
            signature,
        }
    }

    pub fn verify(&self, identity: &poly::Public, ack_namespace: &[u8]) -> bool {
        // Construct signing payload
        let message = ack_message(&self.chunk, &self.epoch);

        // Verify signature
        ops::partial_verify_message(identity, Some(ack_namespace), &message, &self.signature)
            .is_ok()
    }
}

impl<P: Array, D: Digest> Write for Ack<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<P: Array, D: Digest> Read for Ack<P, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = PartialSignature::read(reader)?;
        Ok(Self {
            chunk,
            epoch,
            signature,
        })
    }
}

impl<P: Array, D: Digest> FixedSize for Ack<P, D> {
    const SIZE: usize = Chunk::<P, D>::SIZE + Epoch::SIZE + PartialSignature::SIZE;
}

/// Activity is the type associated with the [`Reporter`](crate::Reporter) trait.
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<C: Verifier, D: Digest> {
    Proposal(Proposal<C, D>),
    Lock(Lock<C::PublicKey, D>),
}

impl<C: Verifier, D: Digest> Write for Activity<C, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Activity::Proposal(proposal) => {
                0u8.write(writer);
                proposal.write(writer);
            }
            Activity::Lock(lock) => {
                1u8.write(writer);
                lock.write(writer);
            }
        }
    }
}

impl<C: Verifier, D: Digest> Read for Activity<C, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Activity::Chunk(Chunk::read(reader)?)),
            1 => Ok(Activity::Lock(Lock::read(reader)?)),
            _ => Err(CodecError::Invalid(
                "consensus::ordered_broadcast::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<C: Verifier, D: Digest> EncodeSize for Activity<C, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Activity::chunk(chunk) => chunk.encode_size(),
            Activity::Lock(lock) => lock.encode_size(),
        }
    }
}

pub fn ack_message<P: Array, D: Digest>(chunk: &Chunk<P, D>, epoch: &Epoch) -> Vec<u8> {
    let mut message = Vec::with_capacity(Chunk::<P, D>::SIZE + Epoch::SIZE);
    chunk.write(&mut message);
    epoch.write(&mut message);
    message
}

pub fn verify_lock<P: Array, D: Digest>(
    public_key: &Public,
    chunk: &Chunk<P, D>,
    epoch: &Epoch,
    signature: &Signature,
    ack_namespace: &[u8],
) -> bool {
    // Construct signing payload
    let message = ack_message(chunk, epoch);

    // Verify signature
    ops::verify_message(public_key, Some(ack_namespace), &message, signature).is_ok()
}

/// Proposal is a message that is generated by a sequencer when proposing a new chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proposal<C: Verifier, D: Digest> {
    /// Chunk that is being proposed.
    pub chunk: Chunk<C::PublicKey, D>,

    /// Signature over the chunk.
    pub signature: C::Signature,
}

impl<C: Verifier, D: Digest> Proposal<C, D> {
    /// Create a new proposal with the given chunk and signature.
    pub fn new(chunk: Chunk<C::PublicKey, D>, signature: C::Signature) -> Self {
        Self { chunk, signature }
    }

    pub fn verify(&self, public_key: &Public, chunk_namespace: &[u8]) -> bool {
        // Verify chunk
        let message = self.chunk.encode();
        C::verify(
            Some(chunk_namespace),
            &message,
            &self.chunk.sequencer,
            &self.signature,
        )
    }
}

impl<C: Verifier, D: Digest> Write for Proposal<C, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
    }
}

impl<C: Verifier, D: Digest> Read for Proposal<C, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = C::Signature::read(reader)?;
        Ok(Self { chunk, signature })
    }
}

impl<C: Verifier, D: Digest> FixedSize for Proposal<C, D> {
    const SIZE: usize = Chunk::<C::PublicKey, D>::SIZE + C::Signature::SIZE;
}

/// Lock is a message that can be generated once `2f + 1` acks are received for a Chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lock<P: Array, D: Digest> {
    /// Chunk that is being locked.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Threshold signature over the chunk.
    pub signature: Signature,
}

impl<P: Array, D: Digest> Lock<P, D> {
    /// Create a new lock with the given chunk, epoch, and signature.
    pub fn new(chunk: Chunk<P, D>, epoch: Epoch, signature: Signature) -> Self {
        Self {
            chunk,
            epoch,
            signature,
        }
    }

    pub fn verify(&self, public_key: &Public, ack_namespace: &[u8]) -> bool {
        verify_lock(
            public_key,
            &self.chunk,
            &self.epoch,
            &self.signature,
            ack_namespace,
        )
    }
}

impl<P: Array, D: Digest> Write for Lock<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<P: Array, D: Digest> Read for Lock<P, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = Signature::read(reader)?;
        Ok(Self {
            chunk,
            epoch,
            signature,
        })
    }
}

impl<P: Array, D: Digest> FixedSize for Lock<P, D> {
    const SIZE: usize = Chunk::<P, D>::SIZE + Epoch::SIZE + Signature::SIZE;
}
