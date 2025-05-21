//! Types used in [`aggregation`](crate::aggregation).

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
    Digest,
};
use commonware_utils::union;
use futures::channel::oneshot;
use std::hash::Hash;

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

    // Proposal Errors
    /// The proposal was canceled by the application
    #[error("Application verify error: {0}")]
    AppProposeCanceled(oneshot::Canceled),

    // P2P Errors
    /// Unable to send a message over the P2P network
    #[error("Unable to send message")]
    UnableToSendMessage,

    // Broadcast errors
    /// The chunk already has a threshold signature
    #[error("Already thresholded")]
    AlreadyThresholded,
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
    /// Epoch is not in the accepted bounds
    #[error("Epoch {0} not in bounds {1} - {2}")]
    EpochNotInBounds(u64, u64, u64),
    /// No identity is known for the specified epoch
    #[error("Unknown identity at epoch {0}")]
    UnknownIdentity(u64),
    /// No validators are known for the specified epoch
    #[error("Unknown validators at epoch {0}")]
    UnknownValidators(u64),
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

pub type Epoch = u64;
pub type Index = u64;

/// Suffix used to identify an acknowledgment (ack) namespace for domain separation.
/// Used when signing and verifying acks to prevent signature reuse across different message types.
const ACK_SUFFIX: &[u8] = b"_AGG_ACK";

/// Returns a suffixed namespace for signing an ack.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for acks cannot be reused for other message types.
#[inline]
fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Item<D: Digest> {
    pub index: Index,
    pub digest: D,
}

impl<D: Digest> Write for Item<D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.index).write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for Item<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = UInt::read(reader)?.into();
        let digest = D::read(reader)?;
        Ok(Self { index, digest })
    }
}

impl<D: Digest> EncodeSize for Item<D> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.digest.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<V: Variant, D: Digest> {
    pub item: Item<D>,
    pub epoch: Epoch,
    pub signature: PartialSignature<V>,
}

impl<V: Variant, D: Digest> Ack<V, D> {
    pub fn verify(&self, namespace: &[u8], identity: &poly::Public<V>) -> bool {
        ops::partial_verify_message::<V>(
            identity,
            Some(ack_namespace(namespace).as_ref()),
            self.item.encode().as_ref(),
            &self.signature,
        )
        .is_ok()
    }

    pub fn sign(namespace: &[u8], epoch: Epoch, share: &Share, item: Item<D>) -> Self {
        let ack_namespace = ack_namespace(namespace);
        let signature = ops::partial_sign_message::<V>(
            share,
            Some(ack_namespace.as_ref()),
            &item.encode().as_ref(),
        );
        Self {
            item,
            epoch,
            signature,
        }
    }
}

impl<V: Variant, D: Digest> Write for Ack<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        UInt(self.epoch).write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Ack<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let epoch = UInt::read(reader)?.into();
        let signature = PartialSignature::<V>::read(reader)?;
        Ok(Self {
            item,
            epoch,
            signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Ack<V, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.signature.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Activity<V: Variant, D: Digest> {
    Ack(Ack<V, D>),
    Lock(Lock<V, D>),
}

impl<V: Variant, D: Digest> Write for Activity<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Activity::Ack(proposal) => {
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

impl<V: Variant, D: Digest> Read for Activity<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Activity::Ack(Ack::read(reader)?)),
            1 => Ok(Activity::Lock(Lock::read(reader)?)),
            _ => Err(CodecError::Invalid(
                "consensus::aggregationActivity",
                "Invalid type",
            )),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Activity<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Activity::Ack(proposal) => proposal.encode_size(),
            Activity::Lock(lock) => lock.encode_size(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock<V: Variant, D: Digest> {
    pub item: Item<D>,
    pub signature: V::Signature,
}

impl<V: Variant, D: Digest> Lock<V, D> {
    pub fn verify(&self, namespace: &[u8], public_key: &V::Public) -> bool {
        ops::verify_message::<V>(
            public_key,
            Some(ack_namespace(namespace).as_ref()),
            self.item.encode().as_ref(),
            &self.signature,
        )
        .is_ok()
    }
}

impl<V: Variant, D: Digest> Write for Lock<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Lock<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let signature = V::Signature::read(reader)?;
        Ok(Self { item, signature })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Lock<V, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.signature.encode_size()
    }
}
