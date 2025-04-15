use commonware_cryptography::{bls12381::primitives::poly::PartialSignature, Digest};
use commonware_utils::Array;

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

/// Wire are messages that are sent over the network.
pub enum Wire<P: Array, D: Digest> {
    Node(Node<P, D>),
    Ack(Ack<P, D>),
}

/// Chunk is a message generated by a sequencer that is broadcasted to all validators.
pub struct Chunk<P: Array, D: Digest> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: u64,

    /// Digest of the payload.
    pub payload: D,
}

/// Parent is a message that contains information about the parent (previous height) of a Chunk.
///
/// The sequencer and height are not provided as they are implied by the sequencer and height of the current chunk.
pub struct Parent<D: Digest> {
    /// Digest of the parent chunk.
    pub digest: D,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Signature over the parent.
    pub signature: D,
}

/// Node is a message from a sequencer that contains a Chunk and a proof that the parent was correctly broadcasted.
///
/// It represents a newly-proposed tip of the chain for the given sequencer.
pub struct Node<P: Array, D: Digest> {
    /// Chunk of the node.
    pub chunk: Chunk<P, D>,

    /// Signature of the sequencer the chunk.
    pub signature: D,

    /// Information about the parent chunk
    ///
    /// This part is not signed over, but it is used to verify that the previous chunk in the chain was correctly broadcast.
    pub parent: Option<Parent<D>>,
}

/// Ack is a message sent by a validator to acknowledge the receipt of a Chunk.
pub struct Ack<P: Array, D: Digest> {
    /// Chunk that is being acknowledged.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Partial signature over the chunk.
    pub signature: PartialSignature,
}
