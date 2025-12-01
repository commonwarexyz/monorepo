//! Types used in [crate::ordered_broadcast].

use crate::types::Epoch;
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops,
        poly::{self, PartialSignature},
        variant::Variant,
    },
    Digest, PublicKey, Signer,
};
use commonware_utils::union;
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
    /// Verification failed because no public key was provided
    #[error("Public key required")]
    PublicKeyRequired,

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
    IAmNotASequencer(Epoch),
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
    /// No polynomial is known for the specified epoch
    #[error("Unknown polynomial at epoch {0}")]
    UnknownPolynomial(Epoch),
    /// No validators are known for the specified epoch
    #[error("Unknown validators at epoch {0}")]
    UnknownValidators(Epoch),
    /// The specified sequencer is not a participant in the epoch
    #[error("Epoch {0} has no sequencer {1}")]
    UnknownSequencer(Epoch, String),
    /// The specified validator is not a participant in the epoch
    #[error("Epoch {0} has no validator {1}")]
    UnknownValidator(Epoch, String),
    /// No cryptographic share is known for the specified epoch
    #[error("Unknown share at epoch {0}")]
    UnknownShare(Epoch),

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
    AckEpochOutsideBounds(Epoch, Epoch, Epoch),
    /// The acknowledgment's height is outside the accepted bounds
    #[error("Invalid ack height {0} outside bounds {1} - {2}")]
    AckHeightOutsideBounds(u64, u64, u64),
    /// The chunk's height is lower than the current tip height
    #[error("Chunk height {0} lower than tip height {1}")]
    ChunkHeightTooLow(u64, u64),

    // Attributable Faults
    /// The chunk conflicts with an existing chunk at the same height
    #[error("Chunk payload mismatch from sequencer {0} at height {1}")]
    ChunkMismatch(String, u64),
}

/// Suffix used to identify a chunk namespace for domain separation.
/// Used when signing and verifying chunks to prevent signature reuse across different message types.
pub const CHUNK_SUFFIX: &[u8] = b"_CHUNK";

/// Suffix used to identify an acknowledgment (ack) namespace for domain separation.
/// Used when signing and verifying acks to prevent signature reuse across different message types.
pub const ACK_SUFFIX: &[u8] = b"_ACK";

/// Returns a suffixed namespace for signing a chunk.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for chunks cannot be reused for other message types.
#[inline]
pub fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

/// Returns a suffixed namespace for signing an ack.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for acks cannot be reused for other message types.
#[inline]
pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

/// Used as the [crate::Automaton::Context] type.
///
/// Carries the necessary context for the automaton to verify a payload, including
/// the sequencer's public key and its sequencer-specific height.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context<P: PublicKey> {
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
pub struct Chunk<P: PublicKey, D: Digest> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: u64,

    /// Digest of the payload.
    pub payload: D,
}

impl<P: PublicKey, D: Digest> Chunk<P, D> {
    /// Create a new chunk with the given sequencer, height, and payload.
    ///
    /// This is the basic unit of data in the ordered broadcast system.
    pub const fn new(sequencer: P, height: u64, payload: D) -> Self {
        Self {
            sequencer,
            height,
            payload,
        }
    }
}

impl<P: PublicKey, D: Digest> Write for Chunk<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.sequencer.write(writer);
        UInt(self.height).write(writer);
        self.payload.write(writer);
    }
}

impl<P: PublicKey, D: Digest> Read for Chunk<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let sequencer = P::read(reader)?;
        let height = UInt::read(reader)?.into();
        let payload = D::read(reader)?;
        Ok(Self {
            sequencer,
            height,
            payload,
        })
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Chunk<P, D> {
    fn encode_size(&self) -> usize {
        self.sequencer.encode_size() + UInt(self.height).encode_size() + self.payload.encode_size()
    }
}

/// Parent is a message that contains information about the parent (previous height) of a Chunk.
///
/// The sequencer and height are not provided as they are implied by the sequencer and height of the current chunk.
/// The parent includes a threshold signature which proves that a quorum of validators have seen and
/// acknowledged the parent chunk, making it an essential part of the chain linking mechanism.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Parent<V: Variant, D: Digest> {
    /// Digest of the parent chunk.
    pub digest: D,

    /// Epoch of the validator set that signed the parent.
    pub epoch: Epoch,

    /// Threshold signature over the parent, proving that a quorum of validators
    /// in the specified epoch have acknowledged the parent chunk.
    pub signature: V::Signature,
}

impl<V: Variant, D: Digest> Parent<V, D> {
    /// Create a new parent with the given digest, epoch, and signature.
    ///
    /// The parent links a chunk to its predecessor in the chain and provides
    /// the threshold signature that proves the predecessor was reliably broadcast.
    pub const fn new(digest: D, epoch: Epoch, signature: V::Signature) -> Self {
        Self {
            digest,
            epoch,
            signature,
        }
    }
}

impl<V: Variant, D: Digest> Write for Parent<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.digest.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Parent<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let digest = D::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = V::Signature::read(reader)?;
        Ok(Self {
            digest,
            epoch,
            signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Parent<V, D> {
    fn encode_size(&self) -> usize {
        self.digest.encode_size() + self.epoch.encode_size() + self.signature.encode_size()
    }
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
pub struct Node<C: PublicKey, V: Variant, D: Digest> {
    /// Chunk of the node.
    pub chunk: Chunk<C, D>,

    /// Signature of the sequencer over the chunk.
    pub signature: C::Signature,

    /// Information about the parent chunk (previous height)
    ///
    /// This part is not signed over, but it is used to verify that the previous chunk
    /// in the chain was correctly broadcast. It contains the threshold signature that
    /// proves a quorum of validators acknowledged the parent.
    ///
    /// For genesis nodes (height = 0), this is None.
    pub parent: Option<Parent<V, D>>,
}

impl<C: PublicKey, V: Variant, D: Digest> Node<C, V, D> {
    /// Create a new node with the given chunk, signature, and parent.
    ///
    /// For genesis nodes (height = 0), parent should be None.
    /// For all other nodes, parent must be provided.
    pub const fn new(
        chunk: Chunk<C, D>,
        signature: C::Signature,
        parent: Option<Parent<V, D>>,
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
        public: &V::Public,
    ) -> Result<Option<Chunk<C, D>>, Error> {
        // Verify chunk
        let chunk_namespace = chunk_namespace(namespace);
        let message = self.chunk.encode();
        if !self
            .chunk
            .sequencer
            .verify(chunk_namespace.as_ref(), &message, &self.signature)
        {
            return Err(Error::InvalidSequencerSignature);
        }
        let Some(parent) = &self.parent else {
            return Ok(None);
        };

        // Verify parent (if present)
        let parent_chunk = Chunk::new(
            self.chunk.sequencer.clone(),
            self.chunk
                .height
                .checked_sub(1)
                .ok_or(Error::ParentMissing)?,
            parent.digest,
        );

        // Verify signature
        let message = Ack::<_, V, _>::payload(&parent_chunk, &parent.epoch);
        let ack_namespace = ack_namespace(namespace);
        if ops::verify_message::<V>(
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
    pub fn sign<S: Signer<PublicKey = C, Signature = C::Signature>>(
        namespace: &[u8],
        signer: &mut S,
        height: u64,
        payload: D,
        parent: Option<Parent<V, D>>,
    ) -> Self {
        let chunk_namespace = chunk_namespace(namespace);
        let pub_key = signer.public_key();
        let chunk = Chunk::new(pub_key, height, payload);
        let signature = signer.sign(chunk_namespace.as_ref(), &chunk.encode());
        Self::new(chunk, signature, parent)
    }
}

impl<C: PublicKey, V: Variant, D: Digest> Write for Node<C, V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
        self.parent.write(writer);
    }
}

impl<C: PublicKey, V: Variant, D: Digest> Read for Node<C, V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = C::Signature::read(reader)?;
        let parent = <Option<Parent<V, D>>>::read(reader)?;
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

impl<C: PublicKey, V: Variant, D: Digest> EncodeSize for Node<C, V, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.signature.encode_size() + self.parent.encode_size()
    }
}

impl<C: PublicKey, V: Variant, D: Digest> Hash for Node<C, V, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chunk.hash(state);
        self.signature.hash(state);
        self.parent.hash(state);
    }
}

impl<C: PublicKey, V: Variant, D: Digest> PartialEq for Node<C, V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk
            && self.signature == other.signature
            && self.parent == other.parent
    }
}

impl<C: PublicKey, V: Variant, D: Digest> Eq for Node<C, V, D> {}

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
pub struct Ack<P: PublicKey, V: Variant, D: Digest> {
    /// Chunk that is being acknowledged.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Partial signature over the chunk.
    /// This is a cryptographic signature that can be combined with other partial
    /// signatures to form a threshold signature once a quorum is reached.
    pub signature: PartialSignature<V>,
}

impl<P: PublicKey, V: Variant, D: Digest> Ack<P, V, D> {
    /// Create a new ack with the given chunk, epoch, and signature.
    pub const fn new(chunk: Chunk<P, D>, epoch: Epoch, signature: PartialSignature<V>) -> Self {
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
        let mut message = Vec::with_capacity(chunk.encode_size() + epoch.encode_size());
        chunk.write(&mut message);
        epoch.write(&mut message);
        message
    }

    /// Verify the Ack.
    ///
    /// This ensures that the partial signature is valid for the given chunk and epoch,
    /// using the provided polynomial (which contains the BLS public polynomial).
    ///
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify(&self, namespace: &[u8], polynomial: &poly::Public<V>) -> bool {
        // Construct signing payload
        let ack_namespace = ack_namespace(namespace);
        let message = Self::payload(&self.chunk, &self.epoch);

        // Verify signature
        ops::partial_verify_message::<V>(
            polynomial,
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
        let signature =
            ops::partial_sign_message::<V>(share, Some(ack_namespace.as_ref()), &message);
        Self::new(chunk, epoch, signature)
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Write for Ack<P, V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Read for Ack<P, V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = PartialSignature::<V>::read(reader)?;
        Ok(Self {
            chunk,
            epoch,
            signature,
        })
    }
}

impl<P: PublicKey, V: Variant, D: Digest> EncodeSize for Ack<P, V, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.epoch.encode_size() + self.signature.encode_size()
    }
}

/// Activity is the type associated with the [crate::Reporter] trait.
///
/// This enum represents the two main types of activities that are reported:
/// 1. Tips - when a new chunk at the latest tip is verified for some sequencer
/// 2. Locks - when a threshold signature is formed for a chunk
///
/// The Reporter is notified of these activities so it can track the state of the system
/// and provide the appropriate information to other components.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<C: PublicKey, V: Variant, D: Digest> {
    /// A new tip for a sequencer
    ///
    /// This activity is only emitted when the application has verified some peer proposal.
    Tip(Proposal<C, D>),
    /// A threshold signature for a chunk, indicating it has been acknowledged by a quorum
    Lock(Lock<C, V, D>),
}

impl<C: PublicKey, V: Variant, D: Digest> Write for Activity<C, V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Tip(proposal) => {
                0u8.write(writer);
                proposal.write(writer);
            }
            Self::Lock(lock) => {
                1u8.write(writer);
                lock.write(writer);
            }
        }
    }
}

impl<C: PublicKey, V: Variant, D: Digest> Read for Activity<C, V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Tip(Proposal::read(reader)?)),
            1 => Ok(Self::Lock(Lock::read(reader)?)),
            _ => Err(CodecError::Invalid(
                "consensus::ordered_broadcast::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<C: PublicKey, V: Variant, D: Digest> EncodeSize for Activity<C, V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Tip(proposal) => proposal.encode_size(),
            Self::Lock(lock) => lock.encode_size(),
        }
    }
}

/// Proposal is a message that is generated by a sequencer when proposing a new chunk.
///
/// This represents a new chunk that has been created by a sequencer and is being
/// broadcast to validators for acknowledgment. It contains the chunk itself and the
/// sequencer's signature over that chunk.
#[derive(Clone, Debug)]
pub struct Proposal<C: PublicKey, D: Digest> {
    /// Chunk that is being proposed.
    pub chunk: Chunk<C, D>,

    /// Signature over the chunk.
    /// This is the sequencer's signature proving authenticity of the chunk.
    pub signature: C::Signature,
}

impl<C: PublicKey, D: Digest> Proposal<C, D> {
    /// Create a new Proposal with the given chunk and signature.
    pub const fn new(chunk: Chunk<C, D>, signature: C::Signature) -> Self {
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
        self.chunk
            .sequencer
            .verify(chunk_namespace.as_ref(), &message, &self.signature)
    }
}

impl<C: PublicKey, D: Digest> Write for Proposal<C, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
    }
}

impl<C: PublicKey, D: Digest> Read for Proposal<C, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = C::Signature::read(reader)?;
        Ok(Self { chunk, signature })
    }
}

impl<C: PublicKey, D: Digest> EncodeSize for Proposal<C, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.signature.encode_size()
    }
}

impl<C: PublicKey, D: Digest> Hash for Proposal<C, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chunk.hash(state);
        self.signature.hash(state);
    }
}

impl<C: PublicKey, D: Digest> PartialEq for Proposal<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk && self.signature == other.signature
    }
}

/// This is needed to implement `Eq` for `Proposal`.
impl<C: PublicKey, D: Digest> Eq for Proposal<C, D> {}

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
pub struct Lock<P: PublicKey, V: Variant, D: Digest> {
    /// Chunk that is being locked.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Threshold signature over the chunk.
    /// This is a cryptographic signature that proves a quorum of validators
    /// have acknowledged the chunk.
    pub signature: V::Signature,
}

impl<P: PublicKey, V: Variant, D: Digest> Lock<P, V, D> {
    /// Create a new Lock with the given chunk, epoch, and signature.
    pub const fn new(chunk: Chunk<P, D>, epoch: Epoch, signature: V::Signature) -> Self {
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
    pub fn verify(&self, namespace: &[u8], public_key: &V::Public) -> bool {
        let message = Ack::<_, V, _>::payload(&self.chunk, &self.epoch);
        let ack_namespace = ack_namespace(namespace);
        ops::verify_message::<V>(
            public_key,
            Some(ack_namespace.as_ref()),
            &message,
            &self.signature,
        )
        .is_ok()
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Write for Lock<P, V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Read for Lock<P, V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = V::Signature::read(reader)?;
        Ok(Self {
            chunk,
            epoch,
            signature,
        })
    }
}

impl<P: PublicKey, V: Variant, D: Digest> EncodeSize for Lock<P, V, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.epoch.encode_size() + self.signature.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::{self, deal_anonymous},
            primitives::{
                group::Element,
                ops::{partial_sign_message, threshold_signature_recover},
                poly::{self, public},
                variant::{MinPk, MinSig},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        PrivateKeyExt as _, Signer,
    };
    use commonware_utils::{quorum, NZU32};
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256Digest {
        Sha256Digest::from([v; 32]) // Simple fixed digest for testing
    }

    // Helper function to create a sample Ed25519 scheme
    fn sample_scheme(v: u64) -> PrivateKey {
        PrivateKey::from_seed(v)
    }

    #[test]
    fn test_chunk_encode_decode() {
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let encoded = chunk.encode();
        let decoded = Chunk::<PublicKey, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(chunk, decoded);
    }

    fn parent_encode_decode<V: Variant>() {
        // Generate proper BLS shares and keys
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        // Create a chunk that would be signed
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 0, sample_digest(1));
        let epoch = Epoch::new(5);

        // Generate partial signatures for the chunk
        let message = Ack::<_, V, _>::payload(&chunk, &epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();

        // Recover threshold signature
        let signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create and test parent
        let parent = Parent::new(sample_digest(1), epoch, signature);
        let encoded = parent.encode();
        let decoded = Parent::<V, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(parent, decoded);

        // Verify the signature is valid
        let identity = poly::public::<V>(&polynomial);
        let lock = Lock::<_, V, _>::new(chunk, epoch, signature);
        assert!(lock.verify(NAMESPACE, identity));
    }

    #[test]
    fn test_parent_encode_decode() {
        parent_encode_decode::<MinPk>();
        parent_encode_decode::<MinSig>();
    }

    fn node_encode_decode<V: Variant>() {
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let chunk_namespace = chunk_namespace(NAMESPACE);

        // Test with no parent (genesis)
        let chunk = Chunk::new(public_key.clone(), 0, sample_digest(1));
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let node = Node::<PublicKey, V, Sha256Digest>::new(chunk, signature, None);
        let encoded = node.encode();
        let decoded = Node::<PublicKey, V, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(decoded.chunk, node.chunk);
        assert_eq!(decoded.signature, node.signature);
        assert_eq!(decoded.parent, node.parent);

        // Test with parent - generate a proper threshold signature
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        // Create parent chunk and signature
        let parent_chunk = Chunk::new(public_key.clone(), 0, sample_digest(0));
        let parent_epoch = Epoch::new(5);

        // Generate partial signatures for the parent chunk
        let parent_message = Ack::<_, V, _>::payload(&parent_chunk, &parent_epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &parent_message))
            .collect();

        // Recover threshold signature for parent
        let parent_signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create proper parent with valid threshold signature
        let parent = Some(Parent::new(
            parent_chunk.payload,
            parent_epoch,
            parent_signature,
        ));

        // Create child node
        let chunk2 = Chunk::new(public_key, 1, sample_digest(2));
        let message2 = chunk2.encode();
        let signature2 = scheme.sign(chunk_namespace.as_ref(), &message2);
        let node2 = Node::<PublicKey, V, Sha256Digest>::new(chunk2, signature2, parent);

        // Test encode/decode
        let encoded2 = node2.encode();
        let decoded2 = Node::<PublicKey, V, Sha256Digest>::decode(encoded2).unwrap();
        assert_eq!(decoded2.chunk, node2.chunk);
        assert_eq!(decoded2.signature, node2.signature);
        assert_eq!(decoded2.parent, node2.parent);

        // Verify that the parent signature is valid
        let identity = poly::public::<V>(&polynomial);
        let lock = Lock::<_, V, _>::new(parent_chunk, parent_epoch, parent_signature);
        assert!(lock.verify(NAMESPACE, identity));
    }

    #[test]
    fn test_node_encode_decode() {
        node_encode_decode::<MinPk>();
        node_encode_decode::<MinSig>();
    }

    fn ack_encode_decode<V: Variant>() {
        let n = 4;
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        let ack = Ack::<_, V, _>::sign(NAMESPACE, &shares[0], chunk, epoch);
        let encoded = ack.encode();
        let decoded = Ack::<PublicKey, V, Sha256Digest>::decode(encoded).unwrap();

        assert_eq!(decoded.chunk, ack.chunk);
        assert_eq!(decoded.epoch, ack.epoch);
        assert_eq!(decoded.signature.index, ack.signature.index);
        assert_eq!(decoded.signature.value, ack.signature.value);

        // Verify signature
        assert!(decoded.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_ack_encode_decode() {
        ack_encode_decode::<MinPk>();
        ack_encode_decode::<MinSig>();
    }

    fn activity_encode_decode<V: Variant>() {
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let chunk_namespace = chunk_namespace(NAMESPACE);

        // Test Proposal
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk.clone(), signature.clone());
        let activity = Activity::<PublicKey, V, _>::Tip(proposal);
        let encoded = activity.encode();
        let decoded = Activity::<PublicKey, V, Sha256Digest>::decode(encoded).unwrap();

        match decoded {
            Activity::Tip(p) => {
                assert_eq!(p.chunk, chunk);
                assert_eq!(p.signature, signature);
            }
            _ => panic!("Decoded activity has wrong type"),
        }

        // Test Lock with proper threshold signature
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let epoch = Epoch::new(5);
        // Generate partial signatures for the chunk
        let lock_message = Ack::<_, V, _>::payload(&chunk, &epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &lock_message))
            .collect();

        // Recover threshold signature
        let bls_signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create lock and verify it
        let lock = Lock::new(chunk.clone(), epoch, bls_signature);
        let identity = poly::public::<V>(&polynomial);
        assert!(lock.verify(NAMESPACE, identity));

        // Test activity with the lock
        let activity = Activity::<PublicKey, V, Sha256Digest>::Lock(lock);
        let encoded = activity.encode();
        let decoded = Activity::<PublicKey, V, Sha256Digest>::decode(encoded).unwrap();

        match decoded {
            Activity::Lock(l) => {
                assert_eq!(l.chunk, chunk);
                assert_eq!(l.epoch, epoch);
                assert_eq!(l.signature, bls_signature);
                assert!(l.verify(NAMESPACE, identity));
            }
            _ => panic!("Decoded activity has wrong type"),
        }
    }

    #[test]
    fn test_activity_encode_decode() {
        activity_encode_decode::<MinPk>();
        activity_encode_decode::<MinSig>();
    }

    #[test]
    fn test_proposal_encode_decode() {
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));

        // Create a properly signed proposal
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);

        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);
        let encoded = proposal.encode();
        let decoded = Proposal::<PublicKey, Sha256Digest>::decode(encoded).unwrap();

        assert_eq!(decoded.chunk, proposal.chunk);
        assert_eq!(decoded.signature, proposal.signature);

        // Verify the decoded proposal
        assert!(decoded.verify(NAMESPACE));
    }

    fn lock_encode_decode<V: Variant>() {
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        // Generate proper BLS shares and threshold signature
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        // Generate partial signatures for the chunk
        let message = Ack::<_, V, _>::payload(&chunk, &epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();

        // Recover threshold signature
        let signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create lock, encode and decode
        let lock = Lock::<_, V, _>::new(chunk, epoch, signature);
        let encoded = lock.encode();
        let decoded = Lock::<PublicKey, V, Sha256Digest>::decode(encoded).unwrap();

        assert_eq!(decoded.chunk, lock.chunk);
        assert_eq!(decoded.epoch, lock.epoch);
        assert_eq!(decoded.signature, lock.signature);

        // Verify the signature in the decoded lock
        let identity = poly::public::<V>(&polynomial);
        assert!(decoded.verify(NAMESPACE, identity));
    }

    #[test]
    fn test_lock_encode_decode() {
        lock_encode_decode::<MinPk>();
        lock_encode_decode::<MinSig>();
    }

    fn node_sign_verify<V: Variant>() {
        let mut scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));
        let identity = public::<V>(&polynomial);

        // Test genesis node (no parent)
        let node = Node::<PublicKey, V, Sha256Digest>::sign(
            NAMESPACE,
            &mut scheme,
            0,
            sample_digest(1),
            None,
        );
        let result = node.verify(NAMESPACE, identity);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test node with parent
        let parent_chunk = Chunk::new(public_key, 0, sample_digest(1));
        let parent_epoch = Epoch::new(5);

        // Create threshold signature for parent
        let message = Ack::<_, V, _>::payload(&parent_chunk, &parent_epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let parent_sigs: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();
        let parent_threshold = threshold_signature_recover::<V, _>(t, &parent_sigs).unwrap();

        let parent = Some(Parent::new(
            parent_chunk.payload,
            parent_epoch,
            parent_threshold,
        ));
        let node = Node::<PublicKey, V, Sha256Digest>::sign(
            NAMESPACE,
            &mut scheme,
            1,
            sample_digest(2),
            parent,
        );

        let result = node.verify(NAMESPACE, identity);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_node_sign_verify() {
        node_sign_verify::<MinPk>();
        node_sign_verify::<MinSig>();
    }

    fn ack_sign_verify<V: Variant>() {
        let n = 4;
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        let ack = Ack::<_, V, _>::sign(NAMESPACE, &shares[0], chunk, epoch);
        assert!(ack.verify(NAMESPACE, &polynomial));

        // Test that verification fails with wrong namespace
        assert!(!ack.verify(b"wrong", &polynomial));
    }

    #[test]
    fn test_ack_sign_verify() {
        ack_sign_verify::<MinPk>();
        ack_sign_verify::<MinSig>();
    }

    fn threshold_recovery<V: Variant>() {
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        // Create t partial signatures
        let acks: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| Ack::<_, V, _>::sign(NAMESPACE, s, chunk.clone(), epoch))
            .collect();

        // Extract partial signatures
        let partials: Vec<_> = acks.iter().map(|a| a.signature.clone()).collect();

        // Recover threshold signature
        let threshold = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create lock with threshold signature
        let lock = Lock::<_, V, _>::new(chunk, epoch, threshold);

        // Verify lock
        let identity = poly::public::<V>(&polynomial);
        assert!(lock.verify(NAMESPACE, identity));
    }

    #[test]
    fn test_threshold_recovery() {
        threshold_recovery::<MinPk>();
        threshold_recovery::<MinSig>();
    }

    fn lock_verify<V: Variant>() {
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));
        let identity = poly::public::<V>(&polynomial);

        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        // Create threshold signature
        let message = Ack::<_, V, _>::payload(&chunk, &epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();
        let threshold = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create lock
        let lock = Lock::<_, V, _>::new(chunk, epoch, threshold);

        // Verify lock
        assert!(lock.verify(NAMESPACE, identity));

        // Test that verification fails with wrong namespace
        assert!(!lock.verify(b"wrong", identity));
    }

    #[test]
    fn test_lock_verify() {
        lock_verify::<MinPk>();
        lock_verify::<MinSig>();
    }

    #[test]
    fn test_proposal_verify() {
        let scheme = sample_scheme(0);
        let chunk = Chunk::new(scheme.public_key(), 42, sample_digest(1));

        // Sign and create proposal
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);

        // Verify proposal
        assert!(proposal.verify(NAMESPACE));

        // Test that verification fails with wrong namespace
        assert!(!proposal.verify(b"wrong"));
    }

    #[test]
    #[should_panic(expected = "ParentOnGenesis")]
    fn test_node_genesis_with_parent_panics() {
        // Try to create a genesis node (height 0) with a parent - should panic on decode
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key.clone(), 0, sample_digest(1));
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        // Generate a valid parent signature
        let n = 4;
        let t = quorum(n);
        let (_, shares) = deal_anonymous::<MinSig>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let parent_chunk = Chunk::new(public_key, 0, sample_digest(0));
        let parent_epoch = Epoch::new(5);
        let parent_message = Ack::<_, MinSig, _>::payload(&parent_chunk, &parent_epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| {
                partial_sign_message::<MinSig>(s, Some(ack_namespace.as_ref()), &parent_message)
            })
            .collect();
        let parent_signature = threshold_signature_recover::<MinSig, _>(t, &partials).unwrap();

        let parent = Parent::new(sample_digest(0), parent_epoch, parent_signature);

        let encoded =
            Node::<PublicKey, MinSig, Sha256Digest>::new(chunk, signature, Some(parent)).encode();
        Node::<PublicKey, MinSig, Sha256Digest>::decode(encoded).unwrap();
    }

    #[test]
    #[should_panic(expected = "ParentMissing")]
    fn test_node_non_genesis_without_parent_panics() {
        // Try to create a non-genesis node (height > 0) without a parent - should panic on decode
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 1, sample_digest(1));
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        let encoded = Node::<PublicKey, MinSig, Sha256Digest>::new(chunk, signature, None).encode();
        Node::<PublicKey, MinSig, Sha256Digest>::decode(encoded).unwrap();
    }

    fn node_verify_invalid_signature<V: Variant>() {
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let n = 4;
        let (polynomial, _) = dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));
        let identity = poly::public::<V>(&polynomial);

        // Create a valid chunk
        let chunk = Chunk::new(public_key, 0, sample_digest(1));

        // Create a valid signature
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);

        // Create a node with valid signature
        let node = Node::<PublicKey, V, Sha256Digest>::new(chunk.clone(), signature, None);

        // Verification should succeed
        assert!(node.verify(NAMESPACE, identity).is_ok());

        // Now create a node with invalid signature
        let tampered_signature = scheme.sign(chunk_namespace.as_ref(), &node.encode());
        let invalid_node = Node::<PublicKey, V, Sha256Digest>::new(chunk, tampered_signature, None);

        // Verification should fail
        assert!(matches!(
            invalid_node.verify(NAMESPACE, identity),
            Err(Error::InvalidSequencerSignature)
        ));
    }

    #[test]
    fn test_node_verify_invalid_signature() {
        node_verify_invalid_signature::<MinPk>();
        node_verify_invalid_signature::<MinSig>();
    }

    fn node_verify_invalid_parent_signature<V: Variant>() {
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();

        // Generate BLS keys for threshold signature verification
        let n = 4;
        let t = quorum(n);
        let (commitment, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        // Create parent and child chunks
        let parent_chunk = Chunk::new(public_key.clone(), 0, sample_digest(0));
        let child_chunk = Chunk::new(public_key, 1, sample_digest(1));
        let epoch = Epoch::new(5);

        // Generate a valid threshold signature for the parent
        let message = Ack::<_, V, _>::payload(&parent_chunk, &epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();
        let signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create parent with valid threshold signature
        let parent = Parent::new(parent_chunk.payload, epoch, signature);

        // Create child node
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = child_chunk.encode();
        let node_signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let node = Node::<PublicKey, V, Sha256Digest>::new(
            child_chunk.clone(),
            node_signature.clone(),
            Some(parent),
        );

        // Get the BLS public key from the commitment
        let identity = poly::public::<V>(&commitment);

        // Verification should succeed
        assert!(node.verify(NAMESPACE, identity).is_ok());

        // Now create a parent with invalid threshold signature
        let (_, wrong_shares) = dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(1), NZU32!(n));

        // Generate threshold signature with the wrong keys
        let partials: Vec<_> = wrong_shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();
        let wrong_signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create parent with wrong threshold signature
        let wrong_parent = Parent::new(parent_chunk.payload, epoch, wrong_signature);

        // Create child node with wrong parent
        let node = Node::<PublicKey, V, Sha256Digest>::new(
            child_chunk,
            node_signature,
            Some(wrong_parent),
        );

        // Verification should fail because the parent signature doesn't verify with the correct public key
        assert!(matches!(
            node.verify(NAMESPACE, identity),
            Err(Error::InvalidThresholdSignature)
        ));
    }

    #[test]
    fn test_node_verify_invalid_parent_signature() {
        node_verify_invalid_parent_signature::<MinPk>();
        node_verify_invalid_parent_signature::<MinSig>();
    }

    fn ack_verify_invalid_signature<V: Variant>() {
        let n = 4;
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        // Create a chunk and ack
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        // Create a valid ack
        let ack = Ack::<_, V, _>::sign(NAMESPACE, &shares[0], chunk.clone(), epoch);

        // Verification should succeed
        assert!(ack.verify(NAMESPACE, &polynomial));

        // Create an ack with invalid signature
        let mut invalid_signature = ack.signature;
        invalid_signature.value.add(&V::Signature::one());
        let invalid_ack = Ack::<_, V, _>::new(chunk, epoch, invalid_signature);

        // Verification should fail
        assert!(!invalid_ack.verify(NAMESPACE, &polynomial));
    }

    #[test]
    fn test_ack_verify_invalid_signature() {
        ack_verify_invalid_signature::<MinPk>();
        ack_verify_invalid_signature::<MinSig>();
    }

    fn ack_verify_wrong_validator<V: Variant>() {
        let n = 4;
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let (wrong_polynomial, _) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(1), NZU32!(n));

        // Create a chunk and ack
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        // Create a valid ack
        let ack = Ack::<_, V, _>::sign(NAMESPACE, &shares[0], chunk, epoch);

        // Verification should succeed with correct polynomial
        assert!(ack.verify(NAMESPACE, &polynomial));

        // Verification should fail with wrong polynomial
        assert!(!ack.verify(NAMESPACE, &wrong_polynomial));
    }

    #[test]
    fn test_ack_verify_wrong_validator() {
        ack_verify_wrong_validator::<MinPk>();
        ack_verify_wrong_validator::<MinSig>();
    }

    fn lock_verify_invalid_signature<V: Variant>() {
        let n = 4;
        let t = quorum(n);
        let (polynomial, shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 42, sample_digest(1));
        let epoch = Epoch::new(5);

        // Generate threshold signature
        let message = Ack::<_, V, _>::payload(&chunk, &epoch);
        let ack_namespace = ack_namespace(NAMESPACE);
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();
        let signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create lock
        let lock = Lock::<_, V, _>::new(chunk.clone(), epoch, signature);

        // Get the BLS public key from the commitment
        let identity = poly::public::<V>(&polynomial);

        // Verification should succeed
        assert!(lock.verify(NAMESPACE, identity));

        let (wrong_polynomial, wrong_shares) =
            dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(1), NZU32!(n));

        // Generate threshold signature with the wrong keys
        let partials: Vec<_> = wrong_shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, Some(ack_namespace.as_ref()), &message))
            .collect();
        let wrong_signature = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Create lock with wrong signature
        let wrong_lock = Lock::<_, V, _>::new(chunk, epoch, wrong_signature);

        // Verification should fail with the original public key
        assert!(!wrong_lock.verify(NAMESPACE, identity));

        // But succeed with the matching wrong identity
        let wrong_identity = poly::public::<V>(&wrong_polynomial);
        assert!(wrong_lock.verify(NAMESPACE, wrong_identity));
    }

    #[test]
    fn test_lock_verify_invalid_signature() {
        lock_verify_invalid_signature::<MinPk>();
        lock_verify_invalid_signature::<MinSig>();
    }

    #[test]
    fn test_proposal_verify_wrong_namespace() {
        let scheme = sample_scheme(0);
        let chunk = Chunk::new(scheme.public_key(), 42, sample_digest(1));

        // Sign and create proposal
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);

        // Verify with correct namespace - should pass
        assert!(proposal.verify(NAMESPACE));

        // Verify with wrong namespace - should fail
        assert!(!proposal.verify(b"wrong_namespace"));
    }

    #[test]
    fn test_proposal_verify_wrong_sequencer() {
        let scheme1 = sample_scheme(0);
        let scheme2 = sample_scheme(1); // Different key

        // Create chunk with scheme1's public key
        let chunk = Chunk::new(scheme1.public_key(), 42, sample_digest(1));

        // But sign it with scheme2 (wrong key)
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme2.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);

        // Verification should fail because the signature doesn't match the sequencer's public key
        assert!(!proposal.verify(NAMESPACE));
    }

    fn node_genesis_with_parent_fails<V: Variant>() {
        // Try to create a node with height 0 and a parent
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 0, sample_digest(1));
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        // Create a parent with a random BLS signature (content doesn't matter for this test)
        let n = 4;
        let (_, shares) = dkg::deal_anonymous::<V>(&mut StdRng::seed_from_u64(0), NZU32!(n));

        let dummy_message = vec![0u8; 32];
        let dummy_sig = partial_sign_message::<V>(&shares[0], None, &dummy_message);

        // Convert the partial signature to a full signature
        let signatures = vec![dummy_sig];
        let full_sig = threshold_signature_recover::<V, _>(1, &signatures).unwrap();

        let parent = Parent::new(sample_digest(0), Epoch::new(5), full_sig);

        // Create the genesis node with a parent - should fail to decode
        let encoded =
            Node::<PublicKey, V, Sha256Digest>::new(chunk, signature, Some(parent)).encode();

        // This should error because genesis nodes can't have parents
        let result = Node::<PublicKey, V, Sha256Digest>::decode(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_genesis_with_parent_fails() {
        node_genesis_with_parent_fails::<MinPk>();
        node_genesis_with_parent_fails::<MinSig>();
    }

    fn node_non_genesis_without_parent_fails<V: Variant>() {
        // Try to create a non-genesis node without a parent
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, 1, sample_digest(1)); // Height > 0
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        // Create the node without a parent - should fail to decode
        let encoded = Node::<PublicKey, V, Sha256Digest>::new(chunk, signature, None).encode();

        // This should error because non-genesis nodes must have parents
        let result = Node::<PublicKey, V, Sha256Digest>::decode(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_non_genesis_without_parent_fails() {
        node_non_genesis_without_parent_fails::<MinPk>();
        node_non_genesis_without_parent_fails::<MinSig>();
    }
}
