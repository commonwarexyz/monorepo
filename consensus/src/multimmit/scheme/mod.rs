//! Signed subjects and the concrete Multimmit signature scheme.
//!
//! # Namespaces
//!
//! A deployment picks one globally unique base namespace. Every signed subject kind signs under
//! the base namespace followed by its own suffix (for example `_VOTE`), so a signature for one
//! kind never verifies as another. [`Namespace`] holds the derived namespaces.
//!
//! # Signed messages
//!
//! Every subject signs the canonical encoding of its object: a transaction-block header, a leader
//! block, or a vote content. Each encoding starts with the object's epoch.

use crate::{
    Epochable,
    multimmit::types::{LeaderBlock, TransactionBlockHeader, VoteContent},
    types::Epoch,
};
use bytes::Bytes;
use commonware_codec::{Encode, ReadExt as _};
use commonware_cryptography::{
    Digest,
    certificate::{Namespace as CertificateNamespace, Subject as CertificateSubject},
};
use commonware_utils::union;

pub mod bls12381;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;

const TRANSACTION_BLOCK_SUFFIX: &[u8] = b"_TRANSACTION_BLOCK";
const LEADER_BLOCK_SUFFIX: &[u8] = b"_LEADER_BLOCK";
const VOTE_SUFFIX: &[u8] = b"_VOTE";
const PROOF_OF_POSSESSION_SUFFIX: &[u8] = b"_PROOF_OF_POSSESSION";

/// Pre-computed namespaces for Multimmit's signed subjects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    /// Namespace for transaction-block signatures.
    pub transaction_block: Vec<u8>,
    /// Namespace for leader-block signatures.
    pub leader_block: Vec<u8>,
    /// Namespace for vote contents and the quorum certificates that aggregate them.
    pub vote: Vec<u8>,
    /// Namespace for ordinary-key proofs of possession.
    pub proof_of_possession: Vec<u8>,
}

impl Namespace {
    /// Derives every subject namespace from a deployment's globally unique base namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            transaction_block: union(namespace, TRANSACTION_BLOCK_SUFFIX),
            leader_block: union(namespace, LEADER_BLOCK_SUFFIX),
            vote: union(namespace, VOTE_SUFFIX),
            proof_of_possession: union(namespace, PROOF_OF_POSSESSION_SUFFIX),
        }
    }
}

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}

/// One signed subject: its kind selects the namespace, and its message is the canonical
/// encoding of the signed object.
#[derive(Clone, Debug)]
pub(crate) enum Subject {
    TransactionBlock(Bytes),
    LeaderBlock(Bytes),
    Vote(Bytes),
}

impl Subject {
    pub(crate) fn transaction_block<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::TransactionBlock(header.encode())
    }

    pub(crate) fn leader_block<D: Digest>(block: &LeaderBlock<D>) -> Self {
        Self::LeaderBlock(block.encode())
    }

    pub(crate) fn vote<D: Digest>(content: &VoteContent<D>) -> Self {
        Self::Vote(content.encode())
    }

    const fn encoded(&self) -> &Bytes {
        match self {
            Self::TransactionBlock(encoded) | Self::LeaderBlock(encoded) | Self::Vote(encoded) => {
                encoded
            }
        }
    }
}

impl CertificateSubject for Subject {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Namespace) -> &'a [u8] {
        match self {
            Self::TransactionBlock(_) => &derived.transaction_block,
            Self::LeaderBlock(_) => &derived.leader_block,
            Self::Vote(_) => &derived.vote,
        }
    }

    fn message(&self) -> Bytes {
        self.encoded().clone()
    }
}

impl Epochable for Subject {
    fn epoch(&self) -> Epoch {
        Epoch::read(&mut self.encoded().clone())
            .expect("every encoded subject starts with its epoch")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{
            BlockRef, CertificateId, ChainId, ChainSet, CodecConfig, Endorsement, Window,
        },
        types::{Height, Round, View},
    };
    use commonware_cryptography::{Hasher as _, Sha256};

    #[test]
    fn encoded_subjects_report_their_object_epoch() {
        let round = Round::new(Epoch::new(u64::MAX), View::new(11));
        let config = CodecConfig::new(1, 1, Window::new(1).unwrap()).unwrap();
        let tip = BlockRef::new(ChainId::new(0), Height::zero(), Sha256::hash(&[b"tip"]));
        let endorsement = Endorsement::new(ChainSet::empty(1), vec![tip], config).unwrap();
        let content =
            VoteContent::new(round, Some(Sha256::hash(&[b"leader"])), true, endorsement).unwrap();
        let header = TransactionBlockHeader::new(
            Epoch::new(300),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"body"]),
        )
        .unwrap();
        let leader = LeaderBlock::new(
            round,
            CertificateId::new(Sha256::hash(&[b"parent vqc"])),
            Sha256::hash(&[b"history"]),
        )
        .unwrap();
        assert_eq!(Subject::vote(&content).epoch(), round.epoch());
        assert_eq!(Subject::leader_block(&leader).epoch(), round.epoch());
        assert_eq!(Subject::transaction_block(&header).epoch(), header.epoch());

        let namespace = Namespace::derive(b"base");
        assert_eq!(Subject::vote(&content).namespace(&namespace), b"base_VOTE");
        assert_eq!(
            Subject::leader_block(&leader).namespace(&namespace),
            b"base_LEADER_BLOCK"
        );
        assert_eq!(
            Subject::transaction_block(&header).namespace(&namespace),
            b"base_TRANSACTION_BLOCK"
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
