//! Untrusted artifact admission and exact verification correlation.

use super::algebra::{validate_lqc, validate_vqc};
use crate::{
    Epochable, Viewable,
    multimmit::{
        scheme::{Unverified, bls12381_threshold::Scheme},
        types::{
            CertificateId, DaCertificate, DaVote, Lqc, NoVote, Nullification, Nullify,
            SignedLeaderBlock, SignedTransactionBlock, Vote, Vqc,
        },
    },
    types::{Attributable, Epoch, Participant, Round, View},
};
use commonware_codec::{Encode, EncodeSize, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use core::fmt;
use rand_core::CryptoRng;
use std::sync::Arc;

const ARTIFACT_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_ARTIFACT";

/// The decoded Multimmit wire objects accepted by the local machine.
///
/// Values in this enum have passed their bounded codec or constructor checks, but remain
/// cryptographically and contextually untrusted until the machine processes a matching verification
/// completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Artifact<V: Variant, D: Digest> {
    /// A producer-authenticated transaction-block header.
    TransactionBlock(SignedTransactionBlock<V, D>),
    /// One attributed data-availability share.
    DaVote(DaVote<V, D>),
    /// A recovered data-availability certificate.
    DaCertificate(DaCertificate<V, D>),
    /// A scheduled leader's signed proposal.
    LeaderBlock(SignedLeaderBlock<V, D>),
    /// A complete consensus vote.
    Vote(Vote<V, D>),
    /// An attributed abstention.
    NoVote(NoVote<V>),
    /// An attributed nullification share.
    Nullify(Nullify<V>),
    /// A recovered nullification certificate.
    Nullification(Nullification<V>),
    /// A view quorum certificate.
    Vqc(Vqc<V, D>),
    /// A leader finalization quorum certificate.
    Lqc(Lqc<V, D>),
}

/// An immutable atomic publication of canonical artifacts.
pub type ArtifactBatch<V, D> = Arc<[Arc<Artifact<V, D>>]>;

/// One untrusted artifact carrying the identifier its decoder already computed.
pub type IdentifiedArtifact<V, D> = (ArtifactId<D>, Artifact<V, D>);

/// One per-leader vote slot represented by an artifact before cryptographic verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalityVoteClaim<D: Digest> {
    round: Round,
    leader: D,
    signer: Participant,
}

impl<D: Digest> FinalityVoteClaim<D> {
    const fn new(round: Round, leader: D, signer: Participant) -> Self {
        Self {
            round,
            leader,
            signer,
        }
    }

    pub(crate) const fn pool(self) -> (Round, D) {
        (self.round, self.leader)
    }

    pub(crate) const fn signer(self) -> Participant {
        self.signer
    }
}

impl<V: Variant, D: Digest> Artifact<V, D> {
    /// Returns this artifact's operation class.
    pub const fn kind(&self) -> ArtifactKind {
        match self {
            Self::TransactionBlock(_) => ArtifactKind::TransactionBlock,
            Self::DaVote(_) => ArtifactKind::DaVote,
            Self::DaCertificate(_) => ArtifactKind::DaCertificate,
            Self::LeaderBlock(_) => ArtifactKind::LeaderBlock,
            Self::Vote(_) => ArtifactKind::Vote,
            Self::NoVote(_) => ArtifactKind::NoVote,
            Self::Nullify(_) => ArtifactKind::Nullify,
            Self::Nullification(_) => ArtifactKind::Nullification,
            Self::Vqc(_) => ArtifactKind::Vqc,
            Self::Lqc(_) => ArtifactKind::Lqc,
        }
    }

    /// Returns the view for a view-scoped artifact.
    pub fn view(&self) -> Option<View> {
        match self {
            Self::TransactionBlock(_) | Self::DaVote(_) | Self::DaCertificate(_) => None,
            Self::LeaderBlock(block) => Some(block.view()),
            Self::Vote(vote) => Some(vote.view()),
            Self::NoVote(vote) => Some(vote.view()),
            Self::Nullify(nullify) => Some(nullify.view()),
            Self::Nullification(nullification) => Some(nullification.view()),
            Self::Vqc(certificate) => Some(certificate.view()),
            Self::Lqc(certificate) => Some(certificate.view()),
        }
    }

    /// Returns the participant for an individually attributed artifact.
    pub fn signer(&self) -> Option<Participant> {
        match self {
            Self::TransactionBlock(block) => Some(block.signer()),
            Self::DaVote(vote) => Some(vote.signer()),
            Self::LeaderBlock(block) => Some(block.signer()),
            Self::Vote(vote) => Some(vote.signer()),
            Self::NoVote(vote) => Some(vote.signer()),
            Self::Nullify(nullify) => Some(nullify.signer()),
            Self::DaCertificate(_) | Self::Nullification(_) | Self::Vqc(_) | Self::Lqc(_) => None,
        }
    }

    /// Returns the artifact's canonical encoded length.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::TransactionBlock(value) => value.encode_size(),
            Self::DaVote(value) => value.encode_size(),
            Self::DaCertificate(value) => value.encode_size(),
            Self::LeaderBlock(value) => value.encode_size(),
            Self::Vote(value) => value.encode_size(),
            Self::NoVote(value) => value.encode_size(),
            Self::Nullify(value) => value.encode_size(),
            Self::Nullification(value) => value.encode_size(),
            Self::Vqc(value) => value.encode_size(),
            Self::Lqc(value) => value.encode_size(),
        }
    }

    /// Computes a domain-separated identifier for the exact encoded artifact.
    pub fn id<H: Hasher<Digest = D>>(&self) -> ArtifactId<D> {
        let kind = [self.kind() as u8];
        let encoded = match self {
            Self::TransactionBlock(value) => value.encode(),
            Self::DaVote(value) => value.encode(),
            Self::DaCertificate(value) => value.encode(),
            Self::LeaderBlock(value) => value.encode(),
            Self::Vote(value) => value.encode(),
            Self::NoVote(value) => value.encode(),
            Self::Nullify(value) => value.encode(),
            Self::Nullification(value) => value.encode(),
            Self::Vqc(value) => value.encode(),
            Self::Lqc(value) => value.encode(),
        };
        ArtifactId(H::hash(&[ARTIFACT_NAMESPACE, &kind, encoded.as_ref()]))
    }

    pub(crate) fn id_with_scratch<H: Hasher<Digest = D>>(
        &self,
        encoded: &mut Vec<u8>,
    ) -> ArtifactId<D> {
        encoded.clear();
        encoded.reserve(self.encoded_len());
        match self {
            Self::TransactionBlock(value) => value.write(encoded),
            Self::DaVote(value) => value.write(encoded),
            Self::DaCertificate(value) => value.write(encoded),
            Self::LeaderBlock(value) => value.write(encoded),
            Self::Vote(value) => value.write(encoded),
            Self::NoVote(value) => value.write(encoded),
            Self::Nullify(value) => value.write(encoded),
            Self::Nullification(value) => value.write(encoded),
            Self::Vqc(value) => value.write(encoded),
            Self::Lqc(value) => value.write(encoded),
        }
        debug_assert_eq!(encoded.len(), self.encoded_len());

        self.id_from_canonical_encoding::<H>(encoded)
    }

    /// Identifies canonical bytes already encoded for this artifact.
    pub(crate) fn id_from_canonical_encoding<H: Hasher<Digest = D>>(
        &self,
        encoded: &[u8],
    ) -> ArtifactId<D> {
        debug_assert_eq!(encoded.len(), self.encoded_len());
        let kind = [self.kind() as u8];
        ArtifactId(H::hash(&[ARTIFACT_NAMESPACE, &kind, encoded]))
    }

    /// Returns whether this artifact may authenticate a far-future view before ancestry is resolved.
    pub(crate) const fn self_certifying_view(&self) -> bool {
        matches!(self, Self::Nullification(_) | Self::Vqc(_) | Self::Lqc(_))
    }

    /// Visits every finality vote slot represented by this artifact in canonical signer order.
    pub(crate) fn visit_finality_vote_claims<H: Hasher<Digest = D>>(
        &self,
        mut visit: impl FnMut(FinalityVoteClaim<D>),
    ) {
        match self {
            Self::Vote(vote) => visit(FinalityVoteClaim::new(
                vote.body().round(),
                vote.body().leader(),
                vote.signer(),
            )),
            Self::Vqc(certificate) => {
                let round = certificate.leader().round();
                let designated = certificate.leader().digest::<H>();
                let mut tally = certificate.tally().signers().iter().peekable();
                let mut conflicting = certificate.conflicting_votes().iter().peekable();
                loop {
                    let tally_signer = tally.peek().copied();
                    let conflicting_signer = conflicting.peek().map(|vote| vote.signer());
                    match (tally_signer, conflicting_signer) {
                        (Some(signer), Some(other)) if signer < other => {
                            tally.next();
                            visit(FinalityVoteClaim::new(round, designated, signer));
                        }
                        (Some(_), Some(_)) => {
                            let vote = conflicting.next().expect("a conflicting vote was peeked");
                            visit(FinalityVoteClaim::new(round, vote.leader(), vote.signer()));
                        }
                        (Some(signer), None) => {
                            tally.next();
                            visit(FinalityVoteClaim::new(round, designated, signer));
                        }
                        (None, Some(_)) => {
                            let vote = conflicting.next().expect("a conflicting vote was peeked");
                            visit(FinalityVoteClaim::new(round, vote.leader(), vote.signer()));
                        }
                        (None, None) => break,
                    }
                }
            }
            Self::Lqc(certificate) => {
                let round = certificate.leader().round();
                let leader = certificate.leader().digest::<H>();
                for signer in certificate.tally().signers().iter() {
                    visit(FinalityVoteClaim::new(round, leader, signer));
                }
            }
            Self::TransactionBlock(_)
            | Self::DaVote(_)
            | Self::DaCertificate(_)
            | Self::LeaderBlock(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_) => {}
        }
    }

    pub(crate) fn dependencies(&self) -> Vec<Dependency<D>> {
        match self {
            Self::LeaderBlock(block) => vec![Dependency::Vqc(block.block().parent())],
            Self::Vote(vote) => vec![Dependency::Leader {
                round: vote.body().round(),
                digest: vote.body().leader(),
            }],
            Self::Vqc(_) | Self::Lqc(_) => Vec::new(),
            Self::TransactionBlock(_)
            | Self::DaVote(_)
            | Self::DaCertificate(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_) => Vec::new(),
        }
    }

    pub(crate) fn provisions<H: Hasher<Digest = D>>(&self) -> Vec<Dependency<D>> {
        match self {
            Self::LeaderBlock(block) => vec![Dependency::Leader {
                round: block.block().round(),
                digest: block.block().digest::<H>(),
            }],
            Self::Vqc(certificate) => {
                vec![
                    Dependency::Vqc(certificate.id::<H>()),
                    Dependency::Leader {
                        round: certificate.leader().round(),
                        digest: certificate.leader().digest::<H>(),
                    },
                ]
            }
            Self::Lqc(certificate) => vec![Dependency::Leader {
                round: certificate.leader().round(),
                digest: certificate.leader().digest::<H>(),
            }],
            Self::TransactionBlock(_)
            | Self::DaVote(_)
            | Self::DaCertificate(_)
            | Self::Vote(_)
            | Self::NoVote(_)
            | Self::Nullify(_)
            | Self::Nullification(_) => Vec::new(),
        }
    }

    /// Borrows this value as a cryptographic verification subject.
    pub const fn unverified(&self) -> Unverified<'_, V, D> {
        match self {
            Self::TransactionBlock(value) => Unverified::TransactionBlock(value),
            Self::DaVote(value) => Unverified::DaVote(value),
            Self::DaCertificate(value) => Unverified::DaCertificate(value),
            Self::LeaderBlock(value) => Unverified::LeaderBlock(value),
            Self::Vote(value) => Unverified::Vote(value),
            Self::NoVote(value) => Unverified::NoVote(value),
            Self::Nullify(value) => Unverified::Nullify(value),
            Self::Nullification(value) => Unverified::Nullification(value),
            Self::Vqc(value) => Unverified::Vqc(value),
            Self::Lqc(value) => Unverified::Lqc(value),
        }
    }
}

impl<V: Variant, D: Digest> Epochable for Artifact<V, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::TransactionBlock(value) => value.epoch(),
            Self::DaVote(value) => value.epoch(),
            Self::DaCertificate(value) => value.epoch(),
            Self::LeaderBlock(value) => value.epoch(),
            Self::Vote(value) => value.epoch(),
            Self::NoVote(value) => value.epoch(),
            Self::Nullify(value) => value.epoch(),
            Self::Nullification(value) => value.epoch(),
            Self::Vqc(value) => value.epoch(),
            Self::Lqc(value) => value.epoch(),
        }
    }
}

/// A stable operation class used for verification grouping and diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ArtifactKind {
    /// Producer transaction-block signature.
    TransactionBlock = 0,
    /// Data-availability share.
    DaVote = 1,
    /// Recovered data-availability certificate.
    DaCertificate = 2,
    /// Leader proposal signature.
    LeaderBlock = 3,
    /// Complete consensus vote.
    Vote = 4,
    /// Attributed abstention.
    NoVote = 5,
    /// Nullification share.
    Nullify = 6,
    /// Recovered nullification certificate.
    Nullification = 7,
    /// View quorum certificate.
    Vqc = 8,
    /// Leader finalization certificate.
    Lqc = 9,
}

/// An immutable prerequisite for contextual admission.
///
/// Cryptographic verification is cached independently of this dependency. Arrival of the missing
/// object therefore retries contextual admission without repeating signature verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dependency<D: Digest> {
    /// The exact parent V-QC named by a leader block.
    Vqc(CertificateId<D>),
    /// The complete leader block named by a vote.
    Leader {
        /// The leader's epoch and view.
        round: Round,
        /// The canonical unsigned leader-block digest.
        digest: D,
    },
}

/// Identifies exact artifact bytes within one epoch.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId<D: Digest>(D);

impl<D: Digest> ArtifactId<D> {
    pub(crate) const fn new(digest: D) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    pub const fn get(self) -> D {
        self.0
    }
}

/// Deterministic ingress order assigned before verification is scheduled.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Observation {
    cohort: u64,
    index: u32,
}

impl Observation {
    pub(crate) const fn new(cohort: u64, index: u32) -> Self {
        Self { cohort, index }
    }

    /// Returns the input cohort.
    pub const fn cohort(self) -> u64 {
        self.cohort
    }

    /// Returns the artifact's index within its cohort.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn index(self) -> u32 {
        self.index
    }
}

/// Identifies an immutable verification job within one machine generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(u64);

impl JobId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Correlates one retained artifact with its verification verdict.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerificationTicket<D: Digest> {
    job: JobId,
    artifact: ArtifactId<D>,
    observation: Observation,
}

impl<D: Digest> VerificationTicket<D> {
    pub(crate) const fn new(job: JobId, artifact: ArtifactId<D>, observation: Observation) -> Self {
        Self {
            job,
            artifact,
            observation,
        }
    }

    /// Returns the issuing job.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn job(self) -> JobId {
        self.job
    }

    /// Returns the exact artifact identifier.
    pub const fn artifact(self) -> ArtifactId<D> {
        self.artifact
    }

    /// Returns the pre-verification observation order.
    pub(crate) const fn observation(self) -> Observation {
        self.observation
    }
}

/// One retained artifact in an immutable verification request.
#[derive(Clone, Debug)]
pub struct VerificationItem<V: Variant, D: Digest> {
    ticket: VerificationTicket<D>,
    artifact: Arc<Artifact<V, D>>,
    peer_attributed: bool,
}

impl<V: Variant, D: Digest> VerificationItem<V, D> {
    pub(crate) const fn new(
        ticket: VerificationTicket<D>,
        artifact: Arc<Artifact<V, D>>,
        peer_attributed: bool,
    ) -> Self {
        Self {
            ticket,
            artifact,
            peer_attributed,
        }
    }

    /// Returns the exact correlation ticket.
    pub const fn ticket(&self) -> VerificationTicket<D> {
        self.ticket
    }

    /// Returns the retained decoded artifact.
    pub fn artifact(&self) -> &Artifact<V, D> {
        &self.artifact
    }

    /// Returns whether the artifact entered through authenticated peer ingress.
    pub(crate) const fn peer_attributed(&self) -> bool {
        self.peer_attributed
    }
}

/// An immutable batch of artifact verification work.
#[derive(Clone, Debug)]
pub struct VerifyJob<V: Variant, D: Digest> {
    id: JobId,
    generation: u64,
    items: Vec<VerificationItem<V, D>>,
}

impl<V: Variant, D: Digest> VerifyJob<V, D> {
    pub(crate) const fn new(
        id: JobId,
        generation: u64,
        items: Vec<VerificationItem<V, D>>,
    ) -> Self {
        Self {
            id,
            generation,
            items,
        }
    }

    /// Returns the job identifier.
    pub const fn id(&self) -> JobId {
        self.id
    }

    /// Returns the machine generation that issued the job.
    #[cfg(any(test, feature = "test-utils"))]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact retained items in observation order.
    pub fn items(&self) -> &[VerificationItem<V, D>] {
        &self.items
    }

    /// Executes this exact job with the concrete Multimmit scheme.
    ///
    /// V-QC and L-QC verdicts also require a coherent application-block ancestry transcript.
    ///
    /// The returned completion contains only tickets and verdicts. The machine retains the exact
    /// artifacts and will reject any completion whose generation, cardinality, or ticket order does
    /// not match this request.
    pub fn verify<R, P, H>(
        &self,
        rng: &mut R,
        scheme: &Scheme<P, V>,
        strategy: &impl Strategy,
    ) -> VerificationCompletion<D>
    where
        R: CryptoRng,
        P: PublicKey,
        H: Hasher<Digest = D>,
    {
        let artifacts = self
            .items
            .iter()
            .map(|item| item.artifact().unverified())
            .collect::<Vec<_>>();
        let verdicts = scheme
            .verify_artifacts::<R, H, D>(rng, &artifacts, strategy)
            .into_iter()
            .zip(&self.items)
            .map(|(valid, item)| {
                let valid = valid
                    && match item.artifact() {
                        Artifact::Vqc(certificate) => {
                            validate_vqc::<H, V, D>(certificate, scheme.codec_config()).is_ok()
                        }
                        Artifact::Lqc(certificate) => {
                            validate_lqc::<H, V, D>(certificate, scheme.codec_config()).is_ok()
                        }
                        _ => true,
                    };
                Verdict::new(item.ticket(), valid)
            })
            .collect();
        VerificationCompletion::new(self.id, self.generation, verdicts)
    }
}

/// The cryptographic verdict for one exact verification ticket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Verdict<D: Digest> {
    ticket: VerificationTicket<D>,
    valid: bool,
}

impl<D: Digest> Verdict<D> {
    /// Creates a verdict for an exact machine-issued ticket.
    pub const fn new(ticket: VerificationTicket<D>, valid: bool) -> Self {
        Self { ticket, valid }
    }

    /// Returns the exact machine-issued ticket.
    pub const fn ticket(self) -> VerificationTicket<D> {
        self.ticket
    }

    /// Returns the artifact-verification result.
    pub const fn valid(self) -> bool {
        self.valid
    }
}

/// Completion of one exact verification job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationCompletion<D: Digest> {
    job: JobId,
    generation: u64,
    verdicts: Vec<Verdict<D>>,
}

impl<D: Digest> VerificationCompletion<D> {
    /// Creates a completion for a machine-issued verification request.
    pub const fn new(job: JobId, generation: u64, verdicts: Vec<Verdict<D>>) -> Self {
        Self {
            job,
            generation,
            verdicts,
        }
    }

    /// Returns the completed job identifier.
    pub const fn job(&self) -> JobId {
        self.job
    }

    /// Returns the issuing machine generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns per-item verdicts in request order.
    pub fn verdicts(&self) -> &[Verdict<D>] {
        &self.verdicts
    }

    pub(crate) fn into_verdicts(self) -> Vec<Verdict<D>> {
        self.verdicts
    }
}

impl<V: Variant, D: Digest> fmt::Display for Artifact<V, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind())
    }
}
