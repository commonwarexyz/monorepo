//! Certificate validation and the derivations it produces for finality.

use super::{Error, FinalTips, Tips, VqcExtraction, tips};
use crate::multimmit::{
    machine::{Held, VqcKind},
    scheme::bls12381_threshold::CertificateVotes,
    types::{
        Artifact, ArtifactId, CertificateId, CodecConfig, DigestedLeader, LeaderBlock, Lqc,
        SelectedCommitments, TipRecord, VoteBody, Vqc,
    },
};
use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::Participant;
use std::sync::Arc;
/// Namespace of the digest by which the finality pool identifies one signer's vote body.
const FINALITY_VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_FINALITY_VOTE";

/// Digest by which the finality pool identifies one signer's vote body.
pub(crate) fn vote_evidence<H, D>(signer: Participant, body: &VoteBody<D>) -> D
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let signer = u64::from(signer.get()).to_be_bytes();
    let body = body.encode();
    H::hash(&[FINALITY_VOTE_NAMESPACE, &signer, body.as_ref()])
}

/// One vote a certificate transcript attests, with the evidence digest the finality pool
/// indexes it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedVote<D: Digest> {
    pub(crate) signer: Participant,
    pub(crate) body: VoteBody<D>,
    pub(crate) evidence: D,
}

impl<D: Digest> VerifiedVote<D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(signer: Participant, body: VoteBody<D>) -> Self {
        let evidence = vote_evidence::<H, D>(signer, &body);
        Self {
            signer,
            body,
            evidence,
        }
    }
}

/// Expensive deterministic outputs derived while validating one V-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedVqc<D: Digest> {
    id: CertificateId<D>,
    leader: D,
    canonical: Bytes,
    tips: Arc<Tips<D>>,
    commitments: SelectedCommitments<D>,
    child_history: Option<D>,
    votes: Vec<VerifiedVote<D>>,
}

impl<D: Digest> ValidatedVqc<D> {
    pub(crate) const fn id(&self) -> CertificateId<D> {
        self.id
    }

    pub(crate) const fn leader(&self) -> D {
        self.leader
    }

    /// Separates the certificate's identity and ordering data from its attested votes.
    pub(crate) fn into_parts(self) -> ValidatedVqcParts<D> {
        ValidatedVqcParts {
            id: self.id,
            canonical: self.canonical,
            tips: self.tips,
            commitments: self.commitments,
            child_history: self.child_history,
        }
    }

    pub(crate) const fn commitments(&self) -> &SelectedCommitments<D> {
        &self.commitments
    }

    /// Takes the attested votes: transcript signers first, then conflicting votes.
    pub(crate) fn take_votes(&mut self) -> Vec<VerifiedVote<D>> {
        core::mem::take(&mut self.votes)
    }

    /// Bytes charged against the completion lane, including expanded attested votes.
    pub(crate) fn owned_bytes(&self) -> Option<usize> {
        let mut bytes = self
            .canonical
            .len()
            .checked_add(self.tips.owned_bytes()?)?
            .checked_add(self.commitments.owned_bytes()?)?
            .checked_add(size_of::<Tips<D>>() + 2 * size_of::<usize>())?
            .checked_add(size_of_val(self.votes.as_slice()))?;
        for vote in &self.votes {
            bytes = bytes
                .checked_add(size_of_val(vote.body.positions()))?
                .checked_add(size_of_val(vote.body.extensions()))?
                .checked_add(4 * size_of::<usize>())?;
            for extension in vote.body.extensions() {
                bytes = bytes.checked_add(size_of_val(extension.payloads()))?;
            }
        }
        Some(bytes)
    }
}

/// The identity and ordering data of one validated V-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedVqcParts<D: Digest> {
    /// The certificate identifier hashed from `canonical`.
    pub(crate) id: CertificateId<D>,
    /// The certificate's canonical encoding.
    pub(crate) canonical: Bytes,
    /// The safe tips the certificate's designated votes select.
    pub(crate) tips: Arc<Tips<D>>,
    /// The contiguous block paths ending at `tips` that the designated votes authenticate.
    pub(crate) commitments: SelectedCommitments<D>,
    /// The history commitment a leader block extending this certificate names, or `None` when the
    /// safe tips and proposed heights do not form a tip record.
    pub(crate) child_history: Option<D>,
}

/// One immutable V-QC and the derivations established for that allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DerivedVqc<V: Variant, D: Digest> {
    pub(crate) artifact: Held<VqcKind, V, D>,
    pub(crate) artifact_id: ArtifactId<D>,
    pub(crate) validated: ValidatedVqc<D>,
    byte_charge: usize,
}

impl<V: Variant, D: Digest> DerivedVqc<V, D> {
    /// Derives and validates the V-QC implied by one L-QC's transcript.
    pub(crate) fn from_lqc<H: Hasher<Digest = D>>(
        certificate: &Lqc<V, D>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let certificate = certificate.derive_vqc(config).map_err(|_| Error::Vote)?;
        let validated = validate_vqc::<H, V, D>(&certificate, config)?;
        Self::new::<H>(certificate, validated)
    }

    /// Pairs a certificate with projections established for its exact canonical bytes.
    pub(crate) fn new<H: Hasher<Digest = D>>(
        certificate: Vqc<V, D>,
        validated: ValidatedVqc<D>,
    ) -> Result<Self, Error> {
        let byte_charge = Self::resident_bytes(&certificate, &validated).ok_or(Error::Vote)?;
        let artifact = Held::<VqcKind, V, D>::new(certificate);
        let artifact_id = artifact
            .arc()
            .id_from_canonical_encoding::<H>(&validated.canonical);
        Ok(Self {
            artifact,
            artifact_id,
            validated,
            byte_charge,
        })
    }

    /// Bytes charged for one retained certificate and its derivations, or `None` on overflow.
    fn resident_bytes(certificate: &Vqc<V, D>, validated: &ValidatedVqc<D>) -> Option<usize> {
        // The encoding bounds payload storage; vector elements and the Arc allocation account
        // for resident transcript structure. This charge conservatively includes shared bytes.
        let tally = certificate.tally();
        let mut bytes = size_of::<Artifact<V, D>>()
            .checked_add(2 * size_of::<usize>())?
            .checked_add(validated.canonical.len())?
            .checked_add(size_of_val(certificate.leader().proposals()))?
            .checked_add(size_of_val(tally.reference_extensions()))?
            .checked_add(size_of_val(tally.deviations()))?
            .checked_add(size_of_val(tally.extension_paths()))?;
        for deviation in tally.deviations() {
            bytes = bytes
                .checked_add(size_of_val(deviation.positions()))?
                .checked_add(size_of_val(deviation.extensions()))?;
        }
        bytes.checked_add(validated.owned_bytes()?)
    }

    pub(crate) const fn owned_bytes(&self) -> usize {
        self.byte_charge
    }
}

/// Expensive deterministic outputs derived while validating one L-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedLqc<V: Variant, D: Digest> {
    /// The designated leader block's digest.
    pub(crate) leader: D,
    /// The final tips and settlement facts the designated votes select.
    pub(crate) tips: FinalTips<D>,
    /// Finality evidence for each designated vote, in signer order.
    pub(crate) votes: Vec<VerifiedVote<D>>,
    /// The V-QC the L-QC implies, with its derivations.
    pub(crate) derived: DerivedVqc<V, D>,
}

impl<V: Variant, D: Digest> ValidatedLqc<V, D> {
    /// Bytes charged against the completion lane; the attested votes are excluded as for
    /// [`ValidatedVqc::owned_bytes`].
    pub(crate) fn owned_bytes(&self) -> Option<usize> {
        self.tips
            .owned_bytes()?
            .checked_add(self.derived.owned_bytes())
    }
}

/// Validates one V-QC and derives its ordering data without finality vote evidence.
pub(crate) fn validate_vqc<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
) -> Result<ValidatedVqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let leader = certificate.leader().digest::<H>();
    let designated = expand_designated_votes(certificate, leader, config)?;
    derive_validated::<H, V, D>(certificate, config, leader, &designated)
}

/// Validates one V-QC using its authenticated transcript expansion and derives finality
/// evidence for every attested vote. The expansion must belong to this certificate.
pub(crate) fn validate_vqc_with_votes<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
    votes: CertificateVotes<D>,
) -> Result<ValidatedVqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let CertificateVotes {
        leader,
        designated,
        conflicting,
    } = votes;
    let mut validated = derive_validated::<H, V, D>(certificate, config, leader, &designated)?;
    validated.votes = designated
        .into_iter()
        .chain(conflicting)
        .map(|(signer, body)| VerifiedVote::new::<H>(signer, body))
        .collect();
    Ok(validated)
}

/// Expands the votes a V-QC tally designates, in signer order.
fn expand_designated_votes<V, D>(
    certificate: &Vqc<V, D>,
    leader: D,
    config: CodecConfig,
) -> Result<Vec<(Participant, VoteBody<D>)>, Error>
where
    V: Variant,
    D: Digest,
{
    certificate
        .expand_votes(leader, config)
        .map_err(|_| Error::Vote)
}

/// Derives a V-QC's identity, tips, and selected commitments from its designated votes.
fn derive_validated<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
    leader: D,
    designated: &[(Participant, VoteBody<D>)],
) -> Result<ValidatedVqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let (canonical, id) = canonical_identity::<H, V, D>(certificate);
    let (tips, ancestry) = VqcExtraction::from_votes::<H, V>(
        DigestedLeader::with_digest(certificate.leader(), leader),
        designated.iter().map(|(signer, body)| (*signer, body)),
        config,
    )?
    .into_parts();
    let commitments = ancestry.selected(
        certificate.leader().round().epoch(),
        tips.blocks().iter().copied(),
    );
    Ok(ValidatedVqc {
        id,
        leader,
        canonical,
        child_history: child_history::<H, V, D>(certificate.leader(), &tips),
        tips: Arc::new(tips),
        commitments,
        votes: Vec::new(),
    })
}

/// Returns the history commitment a leader block extending `leader`'s certified tips names.
///
/// Validation computes it once, off the voter's thread, so every proposal validity check compares
/// against the retained value instead of hashing the tips again.
fn child_history<H, V, D>(leader: &LeaderBlock<V, D>, tips: &Tips<D>) -> Option<D>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    TipRecord::new(
        leader.history(),
        tips.blocks().to_vec(),
        leader.proposed_heights(),
    )
    .ok()
    .map(|record| record.commitment::<H>())
}

/// Returns a V-QC's canonical encoding and the certificate identifier hashed from it.
fn canonical_identity<H, V, D>(certificate: &Vqc<V, D>) -> (Bytes, CertificateId<D>)
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let canonical = certificate.encode();
    let id = CertificateId::from_canonical::<H>(&canonical);
    (canonical, id)
}

/// Validates one L-QC using its authenticated transcript expansion.
///
/// Derives the final tips, finality evidence for every designated vote, and the V-QC the L-QC
/// implies, whose commitments cover both the safe and the final tips. The expansion must belong
/// to this certificate.
pub(crate) fn validate_lqc<H, V, D>(
    certificate: &Lqc<V, D>,
    config: CodecConfig,
    votes: CertificateVotes<D>,
) -> Result<ValidatedLqc<V, D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let leader = certificate.leader();
    let leader_digest = votes.leader;
    let expanded = votes.designated;
    let prepared = tips::PreparedVotes::new_digested::<H, V, _>(
        DigestedLeader::with_digest(leader, leader_digest),
        expanded.iter().map(|(signer, body)| (*signer, body)),
        config,
    )?;
    let tips = FinalTips::from_prepared(&prepared, config)?;
    let votes = expanded
        .into_iter()
        .map(|(signer, body)| VerifiedVote::new::<H>(signer, body))
        .collect();
    let ancestry = prepared.ancestry()?;
    let safe_tips = Tips::from_prepared(&prepared, config)?;
    let commitments = ancestry.selected(
        leader.round().epoch(),
        safe_tips.blocks().iter().chain(tips.blocks()).copied(),
    );
    let vqc = certificate.derive_vqc(config).map_err(|_| Error::Vote)?;
    let (canonical, id) = canonical_identity::<H, V, D>(&vqc);
    let derived = DerivedVqc::new::<H>(
        vqc,
        ValidatedVqc {
            id,
            leader: leader_digest,
            canonical,
            child_history: child_history::<H, V, D>(leader, &safe_tips),
            tips: Arc::new(safe_tips),
            commitments,
            votes: Vec::new(),
        },
    )?;
    Ok(ValidatedLqc {
        derived,
        leader: leader_digest,
        tips,
        votes,
    })
}

/// Checks that `votes` could form a V-QC's designated set for `leader`.
///
/// The signers must be distinct committee members, at least `2f + 1` of them, and every vote's
/// paths must fit one consistent ancestry.
pub(crate) fn validate_vqc_votes<'a, H, V, D>(
    leader: &LeaderBlock<V, D>,
    votes: impl IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
    config: CodecConfig,
) -> Result<(), Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest + 'a,
{
    let prepared = tips::PreparedVotes::new::<H, V, _>(leader, votes, config)?;
    prepared.check_vqc_quorum(config)?;
    prepared.ancestry().map(drop)
}

/// Expensive derivations of one verified certificate, produced off the voter thread.
#[derive(Clone, Debug)]
pub(crate) enum CertificateDerivations<V: Variant, D: Digest> {
    Vqc {
        leader: D,
        votes: Vec<VerifiedVote<D>>,
    },
    Lqc {
        leader: D,
        tips: FinalTips<D>,
        votes: Vec<VerifiedVote<D>>,
        derived: Option<DerivedVqc<V, D>>,
    },
}

impl<V: Variant, D: Digest> From<ValidatedLqc<V, D>> for CertificateDerivations<V, D> {
    fn from(validated: ValidatedLqc<V, D>) -> Self {
        let ValidatedLqc {
            leader,
            tips,
            votes,
            derived,
        } = validated;
        Self::Lqc {
            leader,
            tips,
            votes,
            derived: Some(derived),
        }
    }
}

/// Takes the attested votes out of the validated V-QC, leaving its ordering data in place.
impl<V: Variant, D: Digest> From<&mut ValidatedVqc<D>> for CertificateDerivations<V, D> {
    fn from(validated: &mut ValidatedVqc<D>) -> Self {
        Self::Vqc {
            leader: validated.leader(),
            votes: validated.take_votes(),
        }
    }
}

impl<V: Variant, D: Digest> CertificateDerivations<V, D> {
    pub(crate) fn votes(&self) -> &[VerifiedVote<D>] {
        match self {
            Self::Vqc { votes, .. } | Self::Lqc { votes, .. } => votes,
        }
    }

    pub(crate) const fn take_derived(&mut self) -> Option<DerivedVqc<V, D>> {
        match self {
            Self::Lqc { derived, .. } => derived.take(),
            Self::Vqc { .. } => None,
        }
    }
}
