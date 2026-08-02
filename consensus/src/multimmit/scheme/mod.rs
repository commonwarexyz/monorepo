//! Cryptographic subjects and the concrete Multimmit scheme.

use crate::{
    Epochable,
    multimmit::types::{
        DaCertificate, DaVote, LeaderBlock, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock,
        SignedTransactionBlock, TransactionBlockHeader, Vote, VoteBody, Vqc,
    },
    types::{Epoch, Round},
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::union;

pub mod bls12381_threshold;

const TRANSACTION_BLOCK_SUFFIX: &[u8] = b"_TRANSACTION_BLOCK";
const LEADER_BLOCK_SUFFIX: &[u8] = b"_LEADER_BLOCK";
const DA_VOTE_SUFFIX: &[u8] = b"_DA_VOTE";
const VOTE_SUFFIX: &[u8] = b"_VOTE";
const NOVOTE_SUFFIX: &[u8] = b"_NOVOTE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const PROOF_OF_POSSESSION_SUFFIX: &[u8] = b"_PROOF_OF_POSSESSION";

/// Pre-computed namespaces for Multimmit's signed subjects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// Namespace for transaction-block signatures.
    pub transaction_block: Vec<u8>,
    /// Namespace for leader-block signatures.
    pub leader_block: Vec<u8>,
    /// Namespace for data-availability votes and certificates.
    pub da_vote: Vec<u8>,
    /// Namespace for votes and quorum certificates.
    pub vote: Vec<u8>,
    /// Namespace for abstention signatures.
    pub novote: Vec<u8>,
    /// Namespace for nullification shares and certificates.
    pub nullify: Vec<u8>,
    /// Namespace for ordinary-key proofs of possession.
    pub proof_of_possession: Vec<u8>,
}

impl Namespace {
    /// Derives every subject namespace from a deployment's globally unique base namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            transaction_block: union(namespace, TRANSACTION_BLOCK_SUFFIX),
            leader_block: union(namespace, LEADER_BLOCK_SUFFIX),
            da_vote: union(namespace, DA_VOTE_SUFFIX),
            vote: union(namespace, VOTE_SUFFIX),
            novote: union(namespace, NOVOTE_SUFFIX),
            nullify: union(namespace, NULLIFY_SUFFIX),
            proof_of_possession: union(namespace, PROOF_OF_POSSESSION_SUFFIX),
        }
    }
}

/// A borrowed, structurally checked but cryptographically unverified protocol artifact.
///
/// Batch executors use this closed surface to run cryptography without granting contextual
/// admission authority. Successful verification still returns through the local machine's exact
/// ticket.
#[derive(Copy, Clone, Debug)]
pub enum Unverified<'a, V: Variant, D: Digest> {
    /// A producer-authenticated transaction-block header.
    TransactionBlock(&'a SignedTransactionBlock<V, D>),
    /// One data-availability share.
    DaVote(&'a DaVote<V, D>),
    /// A recovered data-availability certificate.
    DaCertificate(&'a DaCertificate<V, D>),
    /// A leader proposal signature.
    LeaderBlock(&'a SignedLeaderBlock<V, D>),
    /// A complete consensus vote.
    Vote(&'a Vote<V, D>),
    /// An attributed abstention.
    NoVote(&'a NoVote<V>),
    /// A nullification share.
    Nullify(&'a Nullify<V>),
    /// A recovered nullification certificate.
    Nullification(&'a Nullification<V>),
    /// A view quorum certificate.
    Vqc(&'a Vqc<V, D>),
    /// A leader finalization certificate.
    Lqc(&'a Lqc<V, D>),
}

#[derive(Clone, Debug)]
pub(crate) enum Subject {
    TransactionBlock(Epoch, Bytes),
    LeaderBlock(Epoch, Bytes),
    DaVote(Epoch, Bytes),
    Vote(Epoch, Bytes),
    NoVote(Round),
    Nullify(Round),
}

impl Subject {
    pub(crate) fn transaction_block<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::TransactionBlock(header.epoch(), header.encode())
    }

    pub(crate) fn leader_block<V: Variant, D: Digest>(block: &LeaderBlock<V, D>) -> Self {
        Self::LeaderBlock(block.epoch(), block.encode())
    }

    pub(crate) fn da_vote<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::DaVote(header.epoch(), header.encode())
    }

    pub(crate) fn vote<D: Digest>(body: &VoteBody<D>) -> Self {
        Self::Vote(body.epoch(), body.encode())
    }

    pub(crate) fn namespace<'a>(&self, namespace: &'a Namespace) -> &'a [u8] {
        match self {
            Self::TransactionBlock(_, _) => &namespace.transaction_block,
            Self::LeaderBlock(_, _) => &namespace.leader_block,
            Self::DaVote(_, _) => &namespace.da_vote,
            Self::Vote(_, _) => &namespace.vote,
            Self::NoVote(_) => &namespace.novote,
            Self::Nullify(_) => &namespace.nullify,
        }
    }

    pub(crate) fn message(&self) -> Bytes {
        match self {
            Self::TransactionBlock(_, encoded)
            | Self::LeaderBlock(_, encoded)
            | Self::DaVote(_, encoded)
            | Self::Vote(_, encoded) => encoded.clone(),
            Self::NoVote(round) | Self::Nullify(round) => round.encode(),
        }
    }
}

impl Epochable for Subject {
    fn epoch(&self) -> Epoch {
        match self {
            Self::TransactionBlock(epoch, _)
            | Self::LeaderBlock(epoch, _)
            | Self::DaVote(epoch, _)
            | Self::Vote(epoch, _) => *epoch,
            Self::NoVote(round) | Self::Nullify(round) => round.epoch(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use bytes::BytesMut;
    use commonware_codec::Write;

    #[test]
    fn compact_subjects_use_epoch_view_prefix() {
        let round = Round::new(Epoch::new(7), View::new(11));
        let mut prefix = BytesMut::new();
        round.epoch().write(&mut prefix);
        round.view().write(&mut prefix);

        assert_eq!(Subject::NoVote(round).message(), prefix.clone().freeze());
        assert_eq!(Subject::Nullify(round).message(), prefix.freeze());
    }
}
