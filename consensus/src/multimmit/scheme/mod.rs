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
//! # Periods
//!
//! Ordinary keys sign synchronized aggregate signatures, which aggregate cheaply across signers
//! that share a [`Period`]. A key must sign at most one message per period, or anyone can forge
//! its signature on any message in that period. Each period matches a durable local choice:
//!
//! - votes and novotes share one view period, because a node durably takes exactly one stance per
//!   view;
//! - a leader block has its own view period, because the leader also votes in its view; and
//! - transaction-block headers share one period per epoch and height across chains, because each
//!   producer owns exactly one chain and never signs two headers at one height.
//!
//! Threshold subjects (DA votes and nullify shares) are BLS signatures and have no period.
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
    types::{Epoch, Height, Round},
};
use bytes::Bytes;
use commonware_codec::{Encode, ReadExt as _, Write as _};
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
const PROOF_OF_KNOWLEDGE_SUFFIX: &[u8] = b"_PROOF_OF_KNOWLEDGE";
const VIEW_PERIOD_SUFFIX: &[u8] = b"_VIEW_PERIOD";
const LEADER_PERIOD_SUFFIX: &[u8] = b"_LEADER_PERIOD";
const HEIGHT_PERIOD_SUFFIX: &[u8] = b"_HEIGHT_PERIOD";

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
    /// Namespace for ordinary-key proofs of knowledge.
    pub proof_of_knowledge: Vec<u8>,
    /// Prefix of the period shared by votes and novotes in one view.
    pub view_period: Vec<u8>,
    /// Prefix of the period of a leader block in one view.
    pub leader_period: Vec<u8>,
    /// Prefix of the period shared by transaction-block headers at one height.
    pub height_period: Vec<u8>,
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
            proof_of_knowledge: union(namespace, PROOF_OF_KNOWLEDGE_SUFFIX),
            view_period: union(namespace, VIEW_PERIOD_SUFFIX),
            leader_period: union(namespace, LEADER_PERIOD_SUFFIX),
            height_period: union(namespace, HEIGHT_PERIOD_SUFFIX),
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

/// The period an ordinary signature is synchronized on (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Period {
    /// Votes and novotes in one view.
    View(Round),
    /// The leader block of one view.
    Leader(Round),
    /// Transaction-block headers at one height, across every chain.
    Height(Epoch, Height),
}

impl Period {
    /// Encodes this period under the deployment's namespaces.
    pub(crate) fn encode(&self, namespace: &Namespace) -> Bytes {
        let mut encoded = match self {
            Self::View(_) => namespace.view_period.clone(),
            Self::Leader(_) => namespace.leader_period.clone(),
            Self::Height(..) => namespace.height_period.clone(),
        };
        match self {
            Self::View(round) | Self::Leader(round) => round.write(&mut encoded),
            Self::Height(epoch, height) => {
                epoch.write(&mut encoded);
                height.write(&mut encoded);
            }
        }
        encoded.into()
    }
}

/// One signed subject: its kind selects the namespace, and its message is the canonical
/// encoding of the signed object.
#[derive(Clone, Debug)]
pub(crate) enum Subject {
    TransactionBlock {
        epoch: Epoch,
        height: Height,
        encoded: Bytes,
    },
    LeaderBlock {
        round: Round,
        encoded: Bytes,
    },
    DaVote(Bytes),
    Vote {
        round: Round,
        encoded: Bytes,
    },
    NoVote(Round),
    Nullify(Round),
}

impl Subject {
    pub(crate) fn transaction_block<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::TransactionBlock {
            epoch: header.epoch(),
            height: header.height(),
            encoded: header.encode(),
        }
    }

    pub(crate) fn leader_block<V: Variant, D: Digest>(block: &LeaderBlock<V, D>) -> Self {
        Self::LeaderBlock {
            round: block.round(),
            encoded: block.encode(),
        }
    }

    pub(crate) fn da_vote<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self::DaVote(header.encode())
    }

    pub(crate) fn vote<D: Digest>(body: &VoteBody<D>) -> Self {
        Self::Vote {
            round: body.round(),
            encoded: body.encode(),
        }
    }

    /// Returns the period of an ordinary-key subject, or `None` for a threshold subject.
    pub(crate) const fn period(&self) -> Option<Period> {
        match self {
            Self::TransactionBlock { epoch, height, .. } => Some(Period::Height(*epoch, *height)),
            Self::LeaderBlock { round, .. } => Some(Period::Leader(*round)),
            Self::Vote { round, .. } | Self::NoVote(round) => Some(Period::View(*round)),
            Self::DaVote(_) | Self::Nullify(_) => None,
        }
    }
}

impl CertificateSubject for Subject {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Namespace) -> &'a [u8] {
        match self {
            Self::TransactionBlock { .. } => &derived.transaction_block,
            Self::LeaderBlock { .. } => &derived.leader_block,
            Self::DaVote(_) => &derived.da_vote,
            Self::Vote { .. } => &derived.vote,
            Self::NoVote(_) => &derived.novote,
            Self::Nullify(_) => &derived.nullify,
        }
    }

    fn message(&self) -> Bytes {
        match self {
            Self::TransactionBlock { encoded, .. }
            | Self::LeaderBlock { encoded, .. }
            | Self::DaVote(encoded)
            | Self::Vote { encoded, .. } => encoded.clone(),
            Self::NoVote(round) | Self::Nullify(round) => round.encode(),
        }
    }
}

impl Epochable for Subject {
    fn epoch(&self) -> Epoch {
        match self {
            Self::TransactionBlock { epoch, .. } => *epoch,
            Self::DaVote(encoded) => Epoch::read(&mut encoded.clone())
                .expect("every encoded subject starts with its epoch"),
            Self::LeaderBlock { round, .. }
            | Self::Vote { round, .. }
            | Self::NoVote(round)
            | Self::Nullify(round) => round.epoch(),
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
            CodecConfig::new(1, 1, PathLimits::new(1, 0)).unwrap(),
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
            CodecConfig::new(1, 1, PathLimits::new(1, 0)).unwrap(),
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
    fn ordinary_subjects_share_periods_only_across_one_signing_slot() {
        let namespace = Namespace::new(b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST");
        let round = Round::new(Epoch::new(3), View::new(5));
        let body = VoteBody::new(
            round,
            Sha256::hash(&[b"leader"]),
            vec![Position::new(0)],
            vec![Extension::empty()],
            CodecConfig::new(1, 1, PathLimits::new(1, 0)).unwrap(),
        )
        .unwrap();
        let header = |chain| {
            TransactionBlockHeader::new(
                Epoch::new(3),
                ChainId::new(chain),
                Height::new(7),
                Sha256::hash(&[b"parent"]),
                Sha256::hash(&[b"body"]),
            )
            .unwrap()
        };

        // A view's vote and novote share one period, because a node takes one stance per view.
        assert_eq!(Subject::vote(&body).period(), Some(Period::View(round)));
        assert_eq!(Subject::NoVote(round).period(), Some(Period::View(round)));

        // Headers at one height share a period across chains, because each chain has one producer.
        assert_eq!(
            Subject::transaction_block(&header(0)).period(),
            Some(Period::Height(Epoch::new(3), Height::new(7)))
        );
        assert_eq!(
            Subject::transaction_block(&header(0)).period(),
            Subject::transaction_block(&header(1)).period()
        );

        // Threshold subjects are not synchronized on a period.
        assert_eq!(Subject::da_vote(&header(0)).period(), None);
        assert_eq!(Subject::Nullify(round).period(), None);

        // Leader blocks, other views, other epochs, and heights must each encode a distinct period.
        let periods = [
            Period::View(round),
            Period::Leader(round),
            Period::View(Round::new(Epoch::new(3), View::new(6))),
            Period::View(Round::new(Epoch::new(4), View::new(5))),
            Period::Height(Epoch::new(3), Height::new(5)),
            Period::Height(Epoch::new(5), Height::new(3)),
        ];
        let encoded = periods
            .iter()
            .map(|period| period.encode(&namespace))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(encoded.len(), periods.len());
        assert_ne!(
            Period::View(round).encode(&namespace),
            Period::View(round).encode(&Namespace::new(b"_COMMONWARE_CONSENSUS_MULTIMMIT_OTHER"))
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
