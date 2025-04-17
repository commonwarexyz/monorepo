//! Types used in [`ordered_broadcast`](crate::ordered_broadcast).

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Public, Share, Signature},
        ops,
        poly::{self, PartialSignature},
    },
    Digest, Scheme, Verifier,
};
use commonware_utils::{union, Array};
use futures::channel::oneshot;
use std::hash::{Hash, Hasher};

/// Error that may be encountered when interacting with `ordered-broadcast`.
///
/// These errors are categorized into several groups:
/// - Parser errors (missing parent, etc.)
/// - Application verification errors
/// - P2P errors
/// - Broadcast errors (threshold-related issues)
/// - Epoch errors (unknown validators or sequencers)
/// - Peer errors
/// - Signature errors
/// - Ignorable message errors (outside epoch/height bounds)
/// - Attributable faults (conflicting chunks)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Parser Errors
    /// The parent is missing for a non-genesis chunk
    #[error("Missing parent")]
    ParentMissing,
    /// The parent was provided for a genesis chunk (height 0)
    #[error("Parent on genesis chunk")]
    ParentOnGenesis,

    // Application Verification Errors
    /// The verification was canceled by the application
    #[error("Application verify error: {0}")]
    AppVerifyCanceled(oneshot::Canceled),
    /// The application tried to verify a chunk but no tip was found
    #[error("Application verified no tip")]
    AppVerifiedNoTip,
    /// The application verified a chunk but the height doesn't match the tip
    #[error("Application verified height mismatch")]
    AppVerifiedHeightMismatch,
    /// The application verified a chunk but the payload doesn't match the tip
    #[error("Application verified payload mismatch")]
    AppVerifiedPayloadMismatch,

    // P2P Errors
    /// Unable to send a message over the P2P network
    #[error("Unable to send message")]
    UnableToSendMessage,

    // Broadcast errors
    /// The chunk already has a threshold signature
    #[error("Already thresholded")]
    AlreadyThresholded,
    /// I am not a sequencer in the specified epoch
    #[error("I am not a sequencer in epoch {0}")]
    IAmNotASequencer(u64),
    /// Nothing to rebroadcast
    #[error("Nothing to rebroadcast")]
    NothingToRebroadcast,
    /// The broadcast failed
    #[error("Broadcast failed")]
    BroadcastFailed,
    /// A threshold signature is missing
    #[error("Missing threshold")]
    MissingThreshold,
    /// The sequencer in the context doesn't match the expected sequencer
    #[error("Invalid context sequencer")]
    ContextSequencer,
    /// The height in the context is invalid
    #[error("Invalid context height")]
    ContextHeight,

    // Epoch Errors
    /// No identity is known for the specified epoch
    #[error("Unknown identity at epoch {0}")]
    UnknownIdentity(u64),
    /// No validators are known for the specified epoch
    #[error("Unknown validators at epoch {0}")]
    UnknownValidators(u64),
    /// The specified sequencer is not a participant in the epoch
    #[error("Epoch {0} has no sequencer {1}")]
    UnknownSequencer(u64, String),
    /// The specified validator is not a participant in the epoch
    #[error("Epoch {0} has no validator {1}")]
    UnknownValidator(u64, String),
    /// No cryptographic share is known for the specified epoch
    #[error("Unknown share at epoch {0}")]
    UnknownShare(u64),

    // Peer Errors
    /// The sender's public key doesn't match the expected key
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    /// The sequencer's signature is invalid
    #[error("Invalid sequencer signature")]
    InvalidSequencerSignature,
    /// The threshold signature is invalid
    #[error("Invalid threshold signature")]
    InvalidThresholdSignature,
    /// The node signature is invalid
    #[error("Invalid node signature")]
    InvalidNodeSignature,
    /// The acknowledgment signature is invalid
    #[error("Invalid ack signature")]
    InvalidAckSignature,

    // Ignorable Message Errors
    /// The acknowledgment's epoch is outside the accepted bounds
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(u64, u64, u64),
    /// The acknowledgment's height is outside the accepted bounds
    #[error("Invalid ack height {0} outside bounds {1} - {2}")]
    AckHeightOutsideBounds(u64, u64, u64),
    /// The chunk's height is lower than the current tip height
    #[error("Chunk height {0} lower than tip height {1}")]
    ChunkHeightTooLow(u64, u64),

    // Attributable Faults
    /// The chunk conflicts with an existing chunk at the same height
    #[error("Chunk mismatch from sender {0} with height {1}")]
    ChunkMismatch(String, u64),
}

/// Suffix used to identify a chunk namespace for domain separation.
/// Used when signing and verifying chunks to prevent signature reuse across different message types.
const CHUNK_SUFFIX: &[u8] = b"_CHUNK";

/// Suffix used to identify an acknowledgment (ack) namespace for domain separation.
/// Used when signing and verifying acks to prevent signature reuse across different message types.
const ACK_SUFFIX: &[u8] = b"_ACK";

/// Returns a suffixed namespace for signing a chunk.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for chunks cannot be reused for other message types.
#[inline]
fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

/// Returns a suffixed namespace for signing an ack.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for acks cannot be reused for other message types.
#[inline]
fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

/// Used as the [`Index`](crate::Supervisor::Index) type for monitoring epochs.
/// Defines the current set of sequencers and validators.
///
/// This is not a single "View" in the sense of a consensus protocol, but rather a continuous
/// sequence of views in which the set of sequencers and validators is constant. When the set
/// of participants changes, the epoch increments.
pub type Epoch = u64;

/// Used as the [`Automaton::Context`](crate::Automaton::Context) type.
///
/// Carries the necessary context for the automaton to verify a payload, including
/// the sequencer's public key and its sequencer-specific height.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context<P: Array> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: u64,
}

/// Chunk is a message generated by a sequencer that is broadcasted to all validators.
///
/// A chunk represents a unit of data in the ordered broadcast system. Each sequencer
/// maintains its own chain of chunks with monotonically increasing heights. Validators
/// acknowledge chunks with partial signatures, which are then aggregated into threshold
/// signatures to prove reliable broadcast.
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
    ///
    /// This is the basic unit of data in the ordered broadcast system.
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
/// The parent includes a threshold signature which proves that a quorum of validators have seen and
/// acknowledged the parent chunk, making it an essential part of the chain linking mechanism.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Parent<D: Digest> {
    /// Digest of the parent chunk.
    pub digest: D,

    /// Epoch of the validator set that signed the parent.
    pub epoch: Epoch,

    /// Threshold signature over the parent, proving that a quorum of validators
    /// in the specified epoch have acknowledged the parent chunk.
    pub signature: Signature,
}

impl<D: Digest> Parent<D> {
    /// Create a new parent with the given digest, epoch, and signature.
    ///
    /// The parent links a chunk to its predecessor in the chain and provides
    /// the threshold signature that proves the predecessor was reliably broadcast.
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
/// It represents a newly-proposed tip of the chain for the given sequencer. The node includes:
/// 1. The chunk itself (sequencer, height, payload)
/// 2. The sequencer's signature over the chunk
/// 3. For non-genesis nodes (height > 0), proof that the previous chunk was acknowledged by a quorum of validators
///
/// Nodes form a linked chain from each sequencer, ensuring that new chunks can only be added
/// after their predecessors have been properly acknowledged by the validator set.
#[derive(Clone, Debug)]
pub struct Node<C: Verifier, D: Digest> {
    /// Chunk of the node.
    pub chunk: Chunk<C::PublicKey, D>,

    /// Signature of the sequencer over the chunk.
    pub signature: C::Signature,

    /// Information about the parent chunk (previous height)
    ///
    /// This part is not signed over, but it is used to verify that the previous chunk
    /// in the chain was correctly broadcast. It contains the threshold signature that
    /// proves a quorum of validators acknowledged the parent.
    ///
    /// For genesis nodes (height = 0), this is None.
    pub parent: Option<Parent<D>>,
}

impl<C: Verifier, D: Digest> Node<C, D> {
    /// Create a new node with the given chunk, signature, and parent.
    ///
    /// For genesis nodes (height = 0), parent should be None.
    /// For all other nodes, parent must be provided.
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

    /// Verify the Node (and its parent).
    ///
    /// This ensures:
    /// 1. The sequencer's signature over the chunk is valid
    /// 2. For non-genesis nodes, the parent's threshold signature is valid
    ///
    /// If verification is successful, returns:
    /// - None for genesis nodes
    /// - Some(parent_chunk) for non-genesis nodes
    ///
    /// If verification fails, returns an appropriate error.
    pub fn verify(
        &self,
        namespace: &[u8],
        public: Option<&Public>,
    ) -> Result<Option<Chunk<C::PublicKey, D>>, Error> {
        // Verify chunk
        let chunk_namespace = chunk_namespace(namespace);
        let message = self.chunk.encode();
        if !C::verify(
            Some(chunk_namespace.as_ref()),
            &message,
            &self.chunk.sequencer,
            &self.signature,
        ) {
            return Err(Error::InvalidSequencerSignature);
        }
        let Some(parent) = &self.parent else {
            return Ok(None);
        };

        // Verify parent (if present)
        let Some(public) = public else {
            unreachable!("public should always be present when parent is present");
        };
        let parent_chunk = Chunk::new(
            self.chunk.sequencer.clone(),
            self.chunk.height - 1, // Will not parse if height is 0 and parent exists
            parent.digest,
        );

        // Verify signature
        let message = Ack::payload(&parent_chunk, &parent.epoch);
        let ack_namespace = ack_namespace(namespace);
        if ops::verify_message(
            public,
            Some(ack_namespace.as_ref()),
            &message,
            &parent.signature,
        )
        .is_err()
        {
            return Err(Error::InvalidThresholdSignature);
        }
        Ok(Some(parent_chunk))
    }

    /// Generate a new node with the given chunk, signature, (and parent).
    ///
    /// This is used by sequencers to create and sign new nodes for broadcast.
    /// For non-genesis nodes (height > 0), a parent with threshold signature must be provided.
    pub fn sign<S: Scheme<PublicKey = C::PublicKey, Signature = C::Signature>>(
        namespace: &[u8],
        scheme: &mut S,
        height: u64,
        payload: D,
        parent: Option<Parent<D>>,
    ) -> Self {
        let chunk_namespace = chunk_namespace(namespace);
        let chunk = Chunk::new(scheme.public_key(), height, payload);
        let signature = scheme.sign(Some(chunk_namespace.as_ref()), &chunk.encode());
        Self::new(chunk, signature, parent)
    }
}

impl<C: Verifier, D: Digest> Write for Node<C, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
        self.parent.write(writer);
    }
}

impl<C: Verifier, D: Digest> Read for Node<C, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = C::Signature::read(reader)?;
        let parent = <Option<Parent<D>>>::read(reader)?;
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
        Chunk::<C::PublicKey, D>::SIZE + C::Signature::SIZE + self.parent.encode_size()
    }
}

impl<C: Verifier, D: Digest> Hash for Node<C, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chunk.hash(state);
        self.signature.hash(state);
        self.parent.hash(state);
    }
}

impl<C: Verifier, D: Digest> PartialEq for Node<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk
            && self.signature == other.signature
            && self.parent == other.parent
    }
}

impl<C: Verifier, D: Digest> Eq for Node<C, D> {}

/// Ack is a message sent by a validator to acknowledge the receipt of a Chunk.
///
/// When a validator receives and validates a chunk, it sends an Ack containing:
/// 1. The chunk being acknowledged
/// 2. The current epoch
/// 3. A partial signature over the chunk and epoch
///
/// These partial signatures from validators can be aggregated to form a threshold signature
/// once enough validators (a quorum) have acknowledged the chunk. This threshold signature
/// serves as proof that the chunk was reliably broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<P: Array, D: Digest> {
    /// Chunk that is being acknowledged.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Partial signature over the chunk.
    /// This is a cryptographic signature that can be combined with other partial
    /// signatures to form a threshold signature once a quorum is reached.
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

    /// Compute the signing payload for the Ack.
    ///
    /// This constructs the message that is signed by validators when acknowledging a chunk.
    /// It contains both the chunk and the epoch to ensure domain separation and prevent
    /// signature reuse across epochs.
    fn payload(chunk: &Chunk<P, D>, epoch: &Epoch) -> Vec<u8> {
        let mut message = Vec::with_capacity(Chunk::<P, D>::SIZE + Epoch::SIZE);
        chunk.write(&mut message);
        epoch.write(&mut message);
        message
    }

    /// Verify the Ack.
    ///
    /// This ensures that the partial signature is valid for the given chunk and epoch,
    /// using the provided identity (which contains the BLS public polynomial).
    ///
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify(&self, namespace: &[u8], identity: &poly::Public) -> bool {
        // Construct signing payload
        let ack_namespace = ack_namespace(namespace);
        let message = Self::payload(&self.chunk, &self.epoch);

        // Verify signature
        ops::partial_verify_message(
            identity,
            Some(ack_namespace.as_ref()),
            &message,
            &self.signature,
        )
        .is_ok()
    }

    /// Generate a new Ack.
    ///
    /// This is used by validators to create and sign new acknowledgments for chunks.
    /// It creates a partial signature over the chunk and epoch using the provided share.
    pub fn sign(namespace: &[u8], share: &Share, chunk: Chunk<P, D>, epoch: Epoch) -> Self {
        // Construct signing payload
        let ack_namespace = ack_namespace(namespace);
        let message = Self::payload(&chunk, &epoch);

        // Sign message
        let signature = ops::partial_sign_message(share, Some(ack_namespace.as_ref()), &message);
        Self::new(chunk, epoch, signature)
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
///
/// This enum represents the two main types of activities that are reported:
/// 1. Proposals - when a new chunk is proposed by a sequencer
/// 2. Locks - when a threshold signature is formed for a chunk
///
/// The Reporter is notified of these activities so it can track the state of the system
/// and provide the appropriate information to other components.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<C: Verifier, D: Digest> {
    /// A new proposal from a sequencer
    Proposal(Proposal<C, D>),
    /// A threshold signature for a chunk, indicating it has been acknowledged by a quorum
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
            0 => Ok(Activity::Proposal(Proposal::read(reader)?)),
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
            Activity::Proposal(proposal) => proposal.encode_size(),
            Activity::Lock(lock) => lock.encode_size(),
        }
    }
}

/// Proposal is a message that is generated by a sequencer when proposing a new chunk.
///
/// This represents a new chunk that has been created by a sequencer and is being
/// broadcast to validators for acknowledgment. It contains the chunk itself and the
/// sequencer's signature over that chunk.
#[derive(Clone, Debug)]
pub struct Proposal<C: Verifier, D: Digest> {
    /// Chunk that is being proposed.
    pub chunk: Chunk<C::PublicKey, D>,

    /// Signature over the chunk.
    /// This is the sequencer's signature proving authenticity of the chunk.
    pub signature: C::Signature,
}

impl<C: Verifier, D: Digest> Proposal<C, D> {
    /// Create a new Proposal with the given chunk and signature.
    pub fn new(chunk: Chunk<C::PublicKey, D>, signature: C::Signature) -> Self {
        Self { chunk, signature }
    }

    /// Verify the Proposal.
    ///
    /// This ensures that the sequencer's signature over the chunk is valid.
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        // Verify chunk
        let chunk_namespace = chunk_namespace(namespace);
        let message = self.chunk.encode();
        C::verify(
            Some(chunk_namespace.as_ref()),
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

impl<C: Verifier, D: Digest> Hash for Proposal<C, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chunk.hash(state);
        self.signature.hash(state);
    }
}

impl<C: Verifier, D: Digest> PartialEq for Proposal<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk && self.signature == other.signature
    }
}

/// This is needed to implement `Eq` for `Proposal`.
impl<C: Verifier, D: Digest> Eq for Proposal<C, D> {}

/// Lock is a message that can be generated once `2f + 1` acks are received for a Chunk.
///
/// A Lock represents proof that a quorum of validators (at least 2f+1, where f is the
/// maximum number of faulty validators) have acknowledged a chunk. This proof is in the
/// form of a threshold signature that can be verified by anyone with the public key of
/// the validator set.
///
/// The Lock is essential for:
/// 1. Proving that a chunk has been reliably broadcast
/// 2. Allowing sequencers to build chains of chunks
/// 3. Preventing sequencers from creating forks in their chains
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lock<P: Array, D: Digest> {
    /// Chunk that is being locked.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Threshold signature over the chunk.
    /// This is a cryptographic signature that proves a quorum of validators
    /// have acknowledged the chunk.
    pub signature: Signature,
}

impl<P: Array, D: Digest> Lock<P, D> {
    /// Create a new Lock with the given chunk, epoch, and signature.
    pub fn new(chunk: Chunk<P, D>, epoch: Epoch, signature: Signature) -> Self {
        Self {
            chunk,
            epoch,
            signature,
        }
    }

    /// Verify the Lock.
    ///
    /// This ensures that the threshold signature is valid for the given chunk and epoch,
    /// using the provided public key of the validator set.
    ///
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify(&self, namespace: &[u8], public_key: &Public) -> bool {
        let message = Ack::payload(&self.chunk, &self.epoch);
        let ack_namespace = ack_namespace(namespace);
        ops::verify_message(
            public_key,
            Some(ack_namespace.as_ref()),
            &message,
            &self.signature,
        )
        .is_ok()
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
