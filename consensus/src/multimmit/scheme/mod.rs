//! Signed subjects and the signature schemes Multimmit runs on.
//!
//! # Roles
//!
//! Multimmit signs with three independent key roles, each a shared
//! [`certificate`] scheme over its own subject type:
//!
//! - an ordinary [`Aggregator`] signs [`OrdinarySubject`]s: transaction blocks, leader blocks,
//!   votes, and novotes. V-QCs and L-QCs aggregate ordinary attestations over different subjects
//!   into one [`Aggregate`](Aggregator::Aggregate), keyed by their compact signer-to-message
//!   transcripts;
//! - a data-availability [`certificate::Scheme`] signs [`DaSubject`]s and forms DA certificates at
//!   `n - 2f` ([`Available`]); and
//! - a nullification [`certificate::Scheme`] signs [`NullifySubject`]s and forms nullifications
//!   at `2f + 1` ([`N5f1Nullification`]).
//!
//! A role can only sign its own subject type, and every subject kind signs under its own
//! namespace, so a signature of one role never verifies as another. A [`Scheme`] names one
//! scheme per role, and [`Generic`] implements Multimmit's structural checks, signing,
//! verification, and assembly once over any such suite. The concrete suites are:
//!
//! - [`bls12381`]: BLS multisig ordinary keys with BLS threshold DA and nullification keys, the
//!   default;
//! - [`bls12381_sas`]: Pointcheval-Sanders synchronized aggregate ordinary keys with the same
//!   threshold keys (ALPHA, research grade); and
//! - [`ed25519`]: Ed25519 for every role, whose aggregates and certificates list signatures.
//!
//! # Receipts
//!
//! A payment chain's producer turns the DA votes of `n - f` validators into a receipt: a DA
//! certificate whose signers it can count (see
//! [`Parameters::payment_chain`](crate::multimmit::config::Parameters::payment_chain)). Threshold
//! certificates hide their signers, so an epoch with payments needs a suite whose DA role is
//! attributable: [`ed25519`], or a BLS suite with [`bls12381::Aggregate`] DA certificates, which
//! aggregate ordinary-key signatures with a signer bitmap (the specification's one-signature-scheme
//! variant). [`Scheme::da_signers`] counts a certificate's signers.
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
//! Ordinary subjects are [`Synchronized`]. Synchronized aggregate schemes such as
//! [`bls12381_sas`] aggregate cheaply across signers that share a period, and a key must sign at
//! most one message per period, or anyone can forge its signature on any message in that period.
//! Each period matches a durable local choice:
//!
//! - votes and novotes share one view period, because a node durably takes exactly one stance per
//!   view;
//! - a leader block has its own view period, because the leader also votes in its view; and
//! - transaction-block headers share one period per epoch and height across chains, because each
//!   producer owns exactly one chain and never signs two headers at one height; and
//! - DA votes have one period per epoch, chain, and height, because a validator durably chooses at
//!   most one header to DA-vote for at each position.
//!
//! Schemes without periods ignore them.
//!
//! # Known messages
//!
//! Batch verification accepts [`Verified`] messages the node already checked. A known vote or
//! novote is attached to the matching term of a certificate transcript (see
//! [`Term`](commonware_cryptography::certificate::Term)), and a known DA certificate discharges
//! the matching leader-block anchor. A forged or mismatched known message can fail an artifact
//! but never pass one.

use crate::{
    Epochable,
    multimmit::types::{
        ChainId, DaCertificate, LeaderBlock, NoVote, TransactionBlockHeader, Vote, VoteBody,
    },
    types::{Epoch, Height, Round},
};
use bytes::Bytes;
use commonware_codec::{Encode, Read, Write as _};
use commonware_cryptography::{
    Digest, PublicKey,
    certificate::{
        self, Aggregator, Namespace as CertificateNamespace, Subject as CertificateSubject,
        Synchronized, Verifier,
    },
    sha256,
};
use commonware_utils::{Faults, N5f1, faults::N5f1Nullification, union};
use core::{fmt::Debug, hash::Hash};
use num_traits::ToPrimitive;

pub mod bls12381;
pub mod bls12381_sas;
pub mod ed25519;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
mod generic;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "mocks"))]
pub use generic::SignatureVerification;
#[cfg(not(any(test, feature = "mocks", target_arch = "wasm32")))]
pub(crate) use generic::SignatureVerification;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use generic::{CertificateVotes, DaRecoveryError};
pub use generic::{Error, Generic};

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
const DA_PERIOD_SUFFIX: &[u8] = b"_DA_PERIOD";

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
    /// Namespace for ordinary-key registration proofs.
    pub proof_of_knowledge: Vec<u8>,
    /// Prefix of the period shared by votes and novotes in one view.
    pub view_period: Vec<u8>,
    /// Prefix of the period of a leader block in one view.
    pub leader_period: Vec<u8>,
    /// Prefix of the period shared by transaction-block headers at one height.
    pub height_period: Vec<u8>,
    /// Prefix of the period of a DA vote at one chain position.
    pub da_period: Vec<u8>,
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
            da_period: union(namespace, DA_PERIOD_SUFFIX),
        }
    }

    /// Returns the namespace an ordinary-key registration proof for `identity` signs under.
    ///
    /// Binding the proof to the identity key stops one participant from registering another's
    /// ordinary key as its own.
    pub(crate) fn registration(&self, identity: &[u8]) -> Vec<u8> {
        union(&self.proof_of_knowledge, identity)
    }
}

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}

/// The digest type Multimmit instantiates role schemes at.
///
/// Multimmit subjects carry their canonical encodings, so a role's subject type does not depend
/// on the digest parameter of the certificate traits. [`Scheme`] pins that parameter to this type
/// and [`Generic`] always calls role schemes with it.
pub type RoleDigest = sha256::Digest;

/// The field of a suite marker: it owns no values of its parameters and is always `Send` and
/// `Sync`.
type Marker<T> = core::marker::PhantomData<fn() -> T>;

/// The period an ordinary signature is synchronized on (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Period {
    /// Votes and novotes in one view.
    View(Round),
    /// The leader block of one view.
    Leader(Round),
    /// Transaction-block headers at one height, across every chain.
    Height(Epoch, Height),
    /// DA votes at one chain position.
    Da(Epoch, ChainId, Height),
}

impl Period {
    /// Encodes this period under the deployment's namespaces.
    pub(crate) fn encode(&self, namespace: &Namespace) -> Bytes {
        let mut encoded = match self {
            Self::View(_) => namespace.view_period.clone(),
            Self::Leader(_) => namespace.leader_period.clone(),
            Self::Height(..) => namespace.height_period.clone(),
            Self::Da(..) => namespace.da_period.clone(),
        };
        match self {
            Self::View(round) | Self::Leader(round) => round.write(&mut encoded),
            Self::Height(epoch, height) => {
                epoch.write(&mut encoded);
                height.write(&mut encoded);
            }
            Self::Da(epoch, chain, height) => {
                epoch.write(&mut encoded);
                chain.write(&mut encoded);
                height.write(&mut encoded);
            }
        }
        encoded.into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ordinary {
    TransactionBlock {
        epoch: Epoch,
        height: Height,
        encoded: Bytes,
    },
    LeaderBlock {
        round: Round,
        encoded: Bytes,
    },
    Vote {
        round: Round,
        encoded: Bytes,
    },
    NoVote(Round),
}

/// A subject signed with an ordinary key: a transaction-block header, a leader block, a vote
/// body, or a novote round.
///
/// Its kind selects the namespace, its message is the canonical encoding of the signed object,
/// and its [`Synchronized::period`] is the signing slot described in the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrdinarySubject(Ordinary);

impl OrdinarySubject {
    pub(crate) fn transaction_block<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self(Ordinary::TransactionBlock {
            epoch: header.epoch(),
            height: header.height(),
            encoded: header.encode(),
        })
    }

    pub(crate) fn leader_block<S: Scheme, D: Digest>(block: &LeaderBlock<S, D>) -> Self {
        Self(Ordinary::LeaderBlock {
            round: block.round(),
            encoded: block.encode(),
        })
    }

    pub(crate) fn vote<D: Digest>(body: &VoteBody<D>) -> Self {
        Self(Ordinary::Vote {
            round: body.round(),
            encoded: body.encode(),
        })
    }

    pub(crate) const fn novote(round: Round) -> Self {
        Self(Ordinary::NoVote(round))
    }

    /// Returns the period this subject is synchronized on.
    pub(crate) const fn period_kind(&self) -> Period {
        match &self.0 {
            Ordinary::TransactionBlock { epoch, height, .. } => Period::Height(*epoch, *height),
            Ordinary::LeaderBlock { round, .. } => Period::Leader(*round),
            Ordinary::Vote { round, .. } | Ordinary::NoVote(round) => Period::View(*round),
        }
    }
}

impl CertificateSubject for OrdinarySubject {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Namespace) -> &'a [u8] {
        match &self.0 {
            Ordinary::TransactionBlock { .. } => &derived.transaction_block,
            Ordinary::LeaderBlock { .. } => &derived.leader_block,
            Ordinary::Vote { .. } => &derived.vote,
            Ordinary::NoVote(_) => &derived.novote,
        }
    }

    fn message(&self) -> Bytes {
        match &self.0 {
            Ordinary::TransactionBlock { encoded, .. }
            | Ordinary::LeaderBlock { encoded, .. }
            | Ordinary::Vote { encoded, .. } => encoded.clone(),
            Ordinary::NoVote(round) => round.encode(),
        }
    }
}

impl Synchronized for OrdinarySubject {
    fn period(&self, derived: &Namespace) -> Bytes {
        self.period_kind().encode(derived)
    }
}

impl Epochable for OrdinarySubject {
    fn epoch(&self) -> Epoch {
        match &self.0 {
            Ordinary::TransactionBlock { epoch, .. } => *epoch,
            Ordinary::LeaderBlock { round, .. }
            | Ordinary::Vote { round, .. }
            | Ordinary::NoVote(round) => round.epoch(),
        }
    }
}

/// A subject signed with a data-availability key: the canonical encoding of a
/// transaction-block header.
///
/// Its [`Synchronized::period`] is the header's chain position (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaSubject {
    epoch: Epoch,
    chain: ChainId,
    height: Height,
    encoded: Bytes,
}

impl DaSubject {
    pub(crate) fn new<D: Digest>(header: &TransactionBlockHeader<D>) -> Self {
        Self {
            epoch: header.epoch(),
            chain: header.chain(),
            height: header.height(),
            encoded: header.encode(),
        }
    }
}

impl Synchronized for DaSubject {
    fn period(&self, derived: &Namespace) -> Bytes {
        Period::Da(self.epoch, self.chain, self.height).encode(derived)
    }
}

impl CertificateSubject for DaSubject {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Namespace) -> &'a [u8] {
        &derived.da_vote
    }

    fn message(&self) -> Bytes {
        self.encoded.clone()
    }
}

impl Epochable for DaSubject {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// A subject signed with a nullification key: the round to nullify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifySubject(Round);

impl NullifySubject {
    pub(crate) const fn new(round: Round) -> Self {
        Self(round)
    }
}

impl CertificateSubject for NullifySubject {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Namespace) -> &'a [u8] {
        &derived.nullify
    }

    fn message(&self) -> Bytes {
        self.0.encode()
    }
}

impl Epochable for NullifySubject {
    fn epoch(&self) -> Epoch {
        self.0.epoch()
    }
}

/// The `n - 2f` quorum of a data-availability certificate.
///
/// Placement, the DA window, and DA-vote eligibility all use certificates at this quorum. A
/// payment chain's receipt is a certificate with at least `n - f` signers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Available;

impl Faults for Available {
    fn max_faults(n: impl ToPrimitive) -> u32 {
        let n = n
            .to_u32()
            .expect("n must be a non-negative integer that fits in u32");
        n - N5f1::da_quorum(n)
    }
}

/// The DA certificate type of a suite.
pub type DaCertificateOf<S> = <<S as Scheme>::Da as Verifier>::Certificate;

/// The nullification certificate type of a suite.
pub type NullificationOf<S> = <<S as Scheme>::Nullify as Verifier>::Certificate;

/// The V-QC and L-QC aggregate type of a suite.
pub type AggregateOf<S> = <<S as Scheme>::Ordinary as Aggregator>::Aggregate;

/// The signature type of a suite's ordinary keys.
pub type OrdinarySignature<S> = <<S as Scheme>::Ordinary as certificate::Scheme>::Signature;

/// The signature type of a suite's data-availability keys.
pub type DaSignature<S> = <<S as Scheme>::Da as certificate::Scheme>::Signature;

/// The signature type of a suite's nullification keys.
pub type NullifySignature<S> = <<S as Scheme>::Nullify as certificate::Scheme>::Signature;

/// A suite of signature schemes for Multimmit's three key roles.
///
/// Implementors are marker types: protocol objects are generic over a suite, while a [`Generic`]
/// holds one instance of each role scheme for an epoch. Every role must be constructed over the
/// same ordered set of [`Self::PublicKey`] identities.
///
/// # Security
///
/// - [`Self::Ordinary`] aggregates attestations over different subjects, so its keys must be
///   registered in a way that rules out rogue-key aggregates (for example with the proofs
///   [`bls12381::Roster`] verifies).
/// - A scheme synchronized on periods must never sign two ordinary subjects in one period.
///   Multimmit assigns periods to durable signing slots (see the module documentation).
/// - [`Self::Da`] forms certificates at `n - 2f` ([`Available`]), and [`Self::Nullify`] at `2f + 1`.
/// - A DA role whose certificates count their signers must sign at most one header per
///   [`DaSubject`] period when it is synchronized, which Multimmit's durable DA-vote choices
///   guarantee.
pub trait Scheme: Clone + Debug + Default + Eq + Hash + Send + Sync + 'static {
    /// The identity key of every participant.
    type PublicKey: PublicKey;

    /// Signs transaction blocks, leader blocks, votes, and novotes, and aggregates them.
    type Ordinary: for<'a> Aggregator<PublicKey = Self::PublicKey, Subject<'a, RoleDigest> = OrdinarySubject>;

    /// Signs data-availability votes and forms DA certificates.
    type Da: for<'a> certificate::Scheme<
            PublicKey = Self::PublicKey,
            Faults = Available,
            Subject<'a, RoleDigest> = DaSubject,
        >;

    /// Signs nullify shares and forms nullifications.
    type Nullify: for<'a> certificate::Scheme<
            PublicKey = Self::PublicKey,
            Faults = N5f1Nullification,
            Subject<'a, RoleDigest> = NullifySubject,
        >;

    /// Returns the decoding configuration of a DA certificate in a committee of `participants`.
    fn da_certificate_config(participants: usize) -> <DaCertificateOf<Self> as Read>::Cfg;

    /// Returns the decoding configuration of a nullification in a committee of `participants`.
    fn nullification_config(participants: usize) -> <NullificationOf<Self> as Read>::Cfg;

    /// Returns how many distinct signers a DA certificate aggregates, or `None` when the suite's
    /// DA certificates do not reveal their signers (threshold signatures).
    ///
    /// The count is read from the certificate without verifying it.
    fn da_signers(da: &Self::Da, certificate: &DaCertificateOf<Self>) -> Option<usize>;
}

/// A locally verified message that can stand in for part of a batch-verified artifact.
///
/// A node that verified a vote or novote individually already holds its signature over that
/// exact message. When a certificate's transcript reproduces the message, the known attestation
/// is attached to that transcript term: schemes with unique, subtractable signatures discharge
/// it without a pairing, and list schemes accept a listed signature equal to it, so a
/// certificate built from messages the node has already seen verifies at little or no cost.
///
/// A recovered data-availability certificate is likewise known for its header: a leader block
/// anchoring a chain on a certificate the node already holds byte for byte needs no verification
/// for that anchor. A differing certificate for the same header is still verified, so a known
/// message can only remove work, never pass a forgery.
#[derive(Debug)]
pub enum Verified<'a, S: Scheme, D: Digest> {
    /// An ordinary vote whose signature has been verified.
    Vote(&'a Vote<S, D>),
    /// An attributed abstention whose signature has been verified.
    NoVote(&'a NoVote<S>),
    /// A data-availability certificate that has been verified or recovered locally.
    DaCertificate(&'a DaCertificate<S, D>),
}

impl<S: Scheme, D: Digest> Clone for Verified<'_, S, D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Scheme, D: Digest> Copy for Verified<'_, S, D> {}
