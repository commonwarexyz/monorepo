//! Signed subjects and the concrete Multimmit signature scheme.
//!
//! # Namespaces
//!
//! A deployment picks one globally unique base namespace. Every signed subject kind signs under
//! the base namespace followed by its own suffix (for example `_VOTE` or `_DA_VOTE`), so a
//! signature for one kind never verifies as another. [`Namespace`] holds the derived namespaces.
//!
//! # Signed messages
//!
//! Every subject signs the canonical encoding of its object: a transaction-block header, a leader
//! block, a vote body, or the round of a novote or nullify share. Each encoding starts with the
//! object's epoch.
//!
//! # Known messages
//!
//! Batch verification accepts [`Verified`] messages the node already checked. A known vote or
//! novote discharges the matching term of a certificate transcript, and a known DA certificate
//! discharges the matching leader-block anchor. A forged or mismatched known message can fail an
//! artifact but never pass one.

use crate::{
    Epochable,
    multimmit::types::{
        DaCertificate, LeaderBlock, NoVote, TransactionBlockHeader, Vote, VoteBody,
    },
    types::{Epoch, Round},
};
use bytes::Bytes;
use commonware_codec::{Encode, ReadExt as _};
use commonware_cryptography::{
    Digest,
    bls12381::primitives::variant::Variant,
    certificate::{Namespace as CertificateNamespace, Subject as CertificateSubject},
};
use commonware_utils::union;

pub mod bls12381_threshold;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;

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

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}

/// A locally verified view message whose signature can discharge a certificate transcript term.
///
/// A node that verified a vote or novote individually already holds the unique signature over
/// that exact message. When a certificate's transcript reproduces the message, the known
/// signature is subtracted from the aggregate instead of being paid for again with a pairing,
/// so a certificate built from messages the node has already seen verifies without any
/// pairing at all.
///
/// A recovered data-availability certificate is likewise unique for its header: a leader block
/// anchoring a chain on a certificate the node already holds byte for byte needs no pairing for
/// that anchor. A differing certificate for the same header is still paid for, so a known
/// certificate can only remove work, never pass a forgery.
#[derive(Copy, Clone, Debug)]
pub enum Verified<'a, V: Variant, D: Digest> {
    /// An ordinary vote whose signature has been verified.
    Vote(&'a Vote<V, D>),
    /// An attributed abstention whose signature has been verified.
    NoVote(&'a NoVote<V>),
    /// A data-availability certificate that has been verified or recovered locally.
    DaCertificate(&'a DaCertificate<V, D>),
}

/// One signed subject: its kind selects the namespace, and its message is the canonical
/// encoding of the signed object.
#[derive(Clone, Debug)]
pub(crate) enum Subject {
    TransactionBlock(Bytes),
    LeaderBlock(Bytes),
    DaVote(Bytes),
    Vote(Bytes),
    NoVote(Round),
    Nullify(Round),
}

impl Subject {
    pub(crate) fn transaction_block<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::TransactionBlock(header.encode())
    }

    pub(crate) fn leader_block<V: Variant, D: Digest>(block: &LeaderBlock<V, D>) -> Self {
        Self::LeaderBlock(block.encode())
    }

    pub(crate) fn da_vote<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::DaVote(header.encode())
    }

    pub(crate) fn vote<D: Digest>(body: &VoteBody<D>) -> Self {
        Self::Vote(body.encode())
    }
}

impl CertificateSubject for Subject {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Namespace) -> &'a [u8] {
        match self {
            Self::TransactionBlock(_) => &derived.transaction_block,
            Self::LeaderBlock(_) => &derived.leader_block,
            Self::DaVote(_) => &derived.da_vote,
            Self::Vote(_) => &derived.vote,
            Self::NoVote(_) => &derived.novote,
            Self::Nullify(_) => &derived.nullify,
        }
    }

    fn message(&self) -> Bytes {
        match self {
            Self::TransactionBlock(encoded)
            | Self::LeaderBlock(encoded)
            | Self::DaVote(encoded)
            | Self::Vote(encoded) => encoded.clone(),
            Self::NoVote(round) | Self::Nullify(round) => round.encode(),
        }
    }
}

impl Epochable for Subject {
    fn epoch(&self) -> Epoch {
        match self {
            Self::TransactionBlock(encoded)
            | Self::LeaderBlock(encoded)
            | Self::DaVote(encoded)
            | Self::Vote(encoded) => Epoch::read(&mut encoded.clone())
                .expect("every encoded subject starts with its epoch"),
            Self::NoVote(round) | Self::Nullify(round) => round.epoch(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, CodecConfig, Extension,
            PathLimits, Position,
        },
        types::{Epoch, Height, View},
    };
    use bytes::BytesMut;
    use commonware_codec::Write;
    use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::variant::MinSig};

    #[test]
    fn compact_subjects_use_epoch_view_prefix() {
        let round = Round::new(Epoch::new(7), View::new(11));
        let mut prefix = BytesMut::new();
        round.epoch().write(&mut prefix);
        round.view().write(&mut prefix);

        assert_eq!(Subject::NoVote(round).message(), prefix.clone().freeze());
        assert_eq!(Subject::Nullify(round).message(), prefix.freeze());
    }

    #[test]
    fn encoded_subjects_report_their_object_epoch() {
        let round = Round::new(Epoch::new(u64::MAX), View::new(11));
        let body = VoteBody::new(
            round,
            Sha256::hash(&[b"leader"]),
            vec![Position::new(0)],
            vec![Extension::empty()],
            CodecConfig::new(1, 1, PathLimits::new(1, 0).unwrap()).unwrap(),
        )
        .unwrap();
        let header = TransactionBlockHeader::new(
            Epoch::new(300),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"body"]),
        )
        .unwrap();
        let chain = ChainId::new(0);
        let leader = LeaderBlock::<MinSig, _>::new(
            round,
            CertificateId::new(Sha256::hash(&[b"parent vqc"])),
            Sha256::hash(&[b"history"]),
            vec![
                ChainProposal::new(
                    chain,
                    Anchor::Tip(BlockRef::new(
                        chain,
                        Height::zero(),
                        Sha256::hash(&[b"tip"]),
                    )),
                    vec![Sha256::hash(&[b"payload"])],
                    1,
                )
                .unwrap(),
            ],
            CodecConfig::new(1, 1, PathLimits::new(1, 0).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(Subject::vote(&body).epoch(), round.epoch());
        assert_eq!(Subject::leader_block(&leader).epoch(), round.epoch());
        assert_eq!(Subject::transaction_block(&header).epoch(), header.epoch());
        assert_eq!(Subject::da_vote(&header).epoch(), header.epoch());
        assert_eq!(Subject::NoVote(round).epoch(), round.epoch());
        assert_eq!(
            Subject::vote(&body).namespace(&Namespace::derive(b"base")),
            b"base_VOTE"
        );
    }

    #[test]
    fn namespaces_derive_only_from_their_base() {
        let namespace = Namespace::new(b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST");
        assert_eq!(
            namespace,
            Namespace::new(b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST")
        );
        for other in [
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_TES".as_slice(),
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_",
            b"",
        ] {
            assert_ne!(namespace, Namespace::new(other));
        }
    }
}
