//! Types used in [crate::minimmit].

// Re-export shared types for backward compatibility
pub use crate::types::{Attributable, AttributableMap, Context};
use crate::{
    minimmit::scheme,
    types::{Epoch, Participant, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    certificate::{Attestation, Scheme},
    Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{M5f1, N5f1};
use rand_core::CryptoRngCore;
use std::{fmt::Debug, hash::Hash};

/// Proposal represents a proposed block in the Minimmit protocol.
///
/// Unlike Simplex's proposal, Minimmit proposals must include the parent payload digest
/// because multiple proposals can be M-notarized at the same view. Without this field,
/// validators with different M-notarization sets could disagree on which parent a
/// proposal builds on, causing a safety violation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proposal<D: Digest> {
    /// The round in which this proposal is made.
    pub round: Round,
    /// The view of the parent proposal that this one builds upon.
    pub parent: View,
    /// The digest of the parent payload.
    ///
    /// This is required because multiple proposals can be M-notarized at the same view
    /// in Minimmit (M-quorum is 2f+1, smaller than Simplex's n-f). Validators must agree
    /// on which specific parent this proposal extends.
    pub parent_payload: D,
    /// The actual payload/content of the proposal (typically a digest of the block data).
    pub payload: D,
}

impl<D: Digest> Proposal<D> {
    /// Creates a new proposal with the specified round, parent view, parent payload, and payload.
    pub const fn new(round: Round, parent: View, parent_payload: D, payload: D) -> Self {
        Self {
            round,
            parent,
            parent_payload,
            payload,
        }
    }
}

impl<D: Digest> Write for Proposal<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.parent.write(writer);
        self.parent_payload.write(writer);
        self.payload.write(writer);
    }
}

impl<D: Digest> Read for Proposal<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let parent = View::read(reader)?;
        let parent_payload = D::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Self {
            round,
            parent,
            parent_payload,
            payload,
        })
    }
}

impl<D: Digest> EncodeSize for Proposal<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.parent.encode_size()
            + self.parent_payload.encode_size()
            + self.payload.encode_size()
    }
}

impl<D: Digest> Viewable for Proposal<D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<D: Digest> Epochable for Proposal<D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Proposal<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            round: Round::arbitrary(u)?,
            parent: View::arbitrary(u)?,
            parent_payload: D::arbitrary(u)?,
            payload: D::arbitrary(u)?,
        })
    }
}

/// Tracks notarize/nullify votes for a view.
///
/// Each vote type is stored in its own [`AttributableMap`] so a validator can only
/// contribute one vote per phase. The tracker is reused across rounds/views to keep
/// allocations stable.
///
/// Unlike Simplex, Minimmit has no separate finalize vote. Instead, finalization
/// occurs when L-quorum (n-f) notarize votes are collected.
pub struct VoteTracker<S: Scheme, D: Digest> {
    /// Per-signer notarize votes keyed by validator index.
    notarizes: AttributableMap<Notarize<S, D>>,
    /// Per-signer nullify votes keyed by validator index.
    nullifies: AttributableMap<Nullify<S>>,
}

impl<S: Scheme, D: Digest> VoteTracker<S, D> {
    /// Creates a tracker sized for `participants` validators.
    pub fn new(participants: usize) -> Self {
        Self {
            notarizes: AttributableMap::new(participants),
            nullifies: AttributableMap::new(participants),
        }
    }

    /// Inserts a notarize vote if the signer has not already voted.
    pub fn insert_notarize(&mut self, vote: Notarize<S, D>) -> bool {
        self.notarizes.insert(vote)
    }

    /// Inserts a nullify vote if the signer has not already voted.
    pub fn insert_nullify(&mut self, vote: Nullify<S>) -> bool {
        self.nullifies.insert(vote)
    }

    /// Returns the notarize vote for `signer`, if present.
    pub fn notarize(&self, signer: Participant) -> Option<&Notarize<S, D>> {
        self.notarizes.get(signer)
    }

    /// Returns the nullify vote for `signer`, if present.
    pub fn nullify(&self, signer: Participant) -> Option<&Nullify<S>> {
        self.nullifies.get(signer)
    }

    /// Iterates over notarize votes in signer order.
    pub fn iter_notarizes(&self) -> impl Iterator<Item = &Notarize<S, D>> {
        self.notarizes.iter()
    }

    /// Iterates over nullify votes in signer order.
    pub fn iter_nullifies(&self) -> impl Iterator<Item = &Nullify<S>> {
        self.nullifies.iter()
    }

    /// Returns how many notarize votes have been recorded (test-only).
    #[cfg(test)]
    pub fn len_notarizes(&self) -> u32 {
        u32::try_from(self.notarizes.len()).expect("too many notarize votes")
    }

    /// Returns how many nullify votes have been recorded (test-only).
    #[cfg(test)]
    pub fn len_nullifies(&self) -> u32 {
        u32::try_from(self.nullifies.len()).expect("too many nullify votes")
    }

    /// Returns `true` if the given signer has a notarize vote recorded.
    pub fn has_notarize(&self, signer: Participant) -> bool {
        self.notarizes.get(signer).is_some()
    }

    /// Returns `true` if a nullify vote has been recorded for `signer`.
    pub fn has_nullify(&self, signer: Participant) -> bool {
        self.nullifies.get(signer).is_some()
    }
}

/// Identifies the subject of a vote or certificate.
///
/// Implementations use the subject to derive domain-separated message bytes for both
/// individual votes and recovered certificates.
///
/// Unlike Simplex, Minimmit has no `Finalize` subject. Finalization is achieved when
/// L-quorum (n-f) notarize votes are collected for the same proposal.
#[derive(Copy, Clone, Debug)]
pub enum Subject<'a, D: Digest> {
    /// Subject for notarize votes and certificates, carrying the proposal.
    Notarize { proposal: &'a Proposal<D> },
    /// Subject for nullify votes and certificates, scoped to a round.
    Nullify { round: Round },
}

impl<D: Digest> Viewable for Subject<'_, D> {
    fn view(&self) -> View {
        match self {
            Subject::Notarize { proposal } => proposal.view(),
            Subject::Nullify { round } => round.view(),
        }
    }
}

/// Vote represents individual votes ([Notarize], [Nullify]).
///
/// Unlike Simplex, Minimmit has no separate Finalize vote.
#[derive(Clone, Debug, PartialEq)]
pub enum Vote<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S>),
}

impl<S: Scheme, D: Digest> Write for Vote<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Nullify(v) => {
                1u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Vote<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Nullify(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Vote<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Nullify::read(reader)?;
                Ok(Self::Nullify(v))
            }
            _ => Err(Error::Invalid("consensus::minimmit::Vote", "Invalid type")),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Vote<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Nullify(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Vote<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Nullify(v) => v.view(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Vote<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=1)?;
        match tag {
            0 => {
                let v = Notarize::arbitrary(u)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Nullify::arbitrary(u)?;
                Ok(Self::Nullify(v))
            }
            _ => unreachable!(),
        }
    }
}

/// Certificate represents aggregated votes ([MNotarization], [Nullification], [Finalization]).
///
/// In Minimmit:
/// - `MNotarization` requires M-quorum (2f+1) notarize votes
/// - `Nullification` requires M-quorum (2f+1) nullify votes
/// - `Finalization` requires L-quorum (n-f) notarize votes (same vote type, higher threshold)
#[derive(Clone, Debug, PartialEq)]
pub enum Certificate<S: Scheme, D: Digest> {
    /// A recovered certificate for an M-notarization (2f+1 notarize votes).
    MNotarization(MNotarization<S, D>),
    /// A recovered certificate for a nullification (2f+1 nullify votes).
    Nullification(Nullification<S>),
    /// A recovered certificate for a finalization (n-f notarize votes).
    Finalization(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Write for Certificate<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::MNotarization(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Nullification(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Self::Finalization(v) => {
                2u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Certificate<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::MNotarization(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Certificate<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = MNotarization::read_cfg(reader, cfg)?;
                Ok(Self::MNotarization(v))
            }
            1 => {
                let v = Nullification::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(v))
            }
            2 => {
                let v = Finalization::read_cfg(reader, cfg)?;
                Ok(Self::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::minimmit::Certificate",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Certificate<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::MNotarization(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Certificate<S, D> {
    fn view(&self) -> View {
        match self {
            Self::MNotarization(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalization(v) => v.view(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Certificate<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=2)?;
        match tag {
            0 => {
                let v = MNotarization::arbitrary(u)?;
                Ok(Self::MNotarization(v))
            }
            1 => {
                let v = Nullification::arbitrary(u)?;
                Ok(Self::Nullification(v))
            }
            2 => {
                let v = Finalization::arbitrary(u)?;
                Ok(Self::Finalization(v))
            }
            _ => unreachable!(),
        }
    }
}

/// Artifact represents all consensus artifacts (votes and certificates) for storage.
///
/// Used for crash recovery journaling. The voter persists these artifacts to disk
/// so it can rebuild state after a restart.
///
/// Unlike Simplex, Minimmit has no separate Finalize vote or Certification tracking.
/// Finalization occurs when L-quorum (n-f) notarize votes are collected.
#[derive(Clone, Debug, PartialEq)]
pub enum Artifact<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A recovered certificate for an M-notarization (2f+1 notarize votes).
    MNotarization(MNotarization<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S>),
    /// A recovered certificate for a nullification (2f+1 nullify votes).
    Nullification(Nullification<S>),
    /// A recovered certificate for a finalization (n-f notarize votes).
    Finalization(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Write for Artifact<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::MNotarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Self::Nullify(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Self::Nullification(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Self::Finalization(v) => {
                4u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Artifact<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::MNotarization(v) => v.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Artifact<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = MNotarization::read_cfg(reader, cfg)?;
                Ok(Self::MNotarization(v))
            }
            2 => {
                let v = Nullify::read(reader)?;
                Ok(Self::Nullify(v))
            }
            3 => {
                let v = Nullification::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(v))
            }
            4 => {
                let v = Finalization::read_cfg(reader, cfg)?;
                Ok(Self::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::minimmit::Artifact",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Artifact<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::MNotarization(v) => v.view(),
            Self::Nullify(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalization(v) => v.view(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Artifact<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=4)?;
        match tag {
            0 => Ok(Self::Notarize(Notarize::arbitrary(u)?)),
            1 => Ok(Self::MNotarization(MNotarization::arbitrary(u)?)),
            2 => Ok(Self::Nullify(Nullify::arbitrary(u)?)),
            3 => Ok(Self::Nullification(Nullification::arbitrary(u)?)),
            4 => Ok(Self::Finalization(Finalization::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

/// Validator vote that endorses a proposal for notarization.
///
/// In Minimmit, notarize votes serve dual purposes:
/// - M-quorum (2f+1) produces an MNotarization
/// - L-quorum (n-f) produces a Finalization
#[derive(Clone, Debug)]
pub struct Notarize<S: Scheme, D: Digest> {
    /// Proposal being notarized.
    pub proposal: Proposal<D>,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<S: Scheme, D: Digest> Notarize<S, D> {
    /// Signs a notarize vote for the provided proposal.
    pub fn sign(scheme: &S, proposal: Proposal<D>) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(Subject::Notarize {
            proposal: &proposal,
        })?;

        Some(Self {
            proposal,
            attestation,
        })
    }

    /// Verifies the notarize vote against the provided signing scheme.
    ///
    /// This ensures that the notarize signature is valid for the claimed proposal.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRngCore,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(
            rng,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.attestation,
            strategy,
        )
    }

    /// Returns the round associated with this notarize vote.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Notarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.attestation == other.attestation
    }
}

impl<S: Scheme, D: Digest> Eq for Notarize<S, D> {}

impl<S: Scheme, D: Digest> Hash for Notarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.attestation.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Notarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.attestation.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Notarize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.attestation.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Notarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let attestation = Attestation::read(reader)?;

        Ok(Self {
            proposal,
            attestation,
        })
    }
}

impl<S: Scheme, D: Digest> Attributable for Notarize<S, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer
    }
}

impl<S: Scheme, D: Digest> Epochable for Notarize<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Notarize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Notarize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self {
            proposal,
            attestation,
        })
    }
}

/// M-notarization certificate recovered from M-quorum (2f+1) notarize votes.
///
/// When a proposal receives 2f+1 notarize votes, it is M-notarized. This allows
/// the view to progress but does not yet finalize the block.
///
/// Some signing schemes (like threshold schemes) embed an additional randomness
/// seed in the certificate.
#[derive(Clone, Debug)]
pub struct MNotarization<S: Scheme, D: Digest> {
    /// The proposal that has been M-notarized.
    pub proposal: Proposal<D>,
    /// The recovered certificate for the proposal.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> MNotarization<S, D> {
    /// Builds an M-notarization certificate from notarize votes for the same proposal.
    ///
    /// Requires M-quorum (2f+1) votes.
    pub fn from_notarizes<'a, I>(scheme: &S, notarizes: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Notarize<S, D>>,
        I::IntoIter: Send,
    {
        let mut iter = notarizes.into_iter();
        let first = iter.next()?;
        let proposal = first.proposal.clone();
        let mut attestations = vec![first.attestation.clone()];

        for notarize in iter {
            if notarize.proposal != proposal {
                return None;
            }
            attestations.push(notarize.attestation.clone());
        }

        let certificate = scheme.assemble::<_, M5f1>(attestations, strategy)?;

        Some(Self {
            proposal,
            certificate,
        })
    }

    /// Verifies the M-notarization certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed proposal with M-quorum.
    pub fn verify<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_certificate::<_, D, M5f1>(
            rng,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.certificate,
            strategy,
        )
    }

    /// Returns the round associated with the M-notarized proposal.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for MNotarization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: Scheme, D: Digest> Eq for MNotarization<S, D> {}

impl<S: Scheme, D: Digest> Hash for MNotarization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for MNotarization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for MNotarization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for MNotarization<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

impl<S: Scheme, D: Digest> Epochable for MNotarization<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for MNotarization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for MNotarization<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self {
            proposal,
            certificate,
        })
    }
}

/// Validator vote for nullifying the current round, i.e. skip the current round.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
#[derive(Clone, Debug)]
pub struct Nullify<S: Scheme> {
    /// The round to be nullified (skipped).
    pub round: Round,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<S: Scheme> PartialEq for Nullify<S> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.attestation == other.attestation
    }
}

impl<S: Scheme> Eq for Nullify<S> {}

impl<S: Scheme> Hash for Nullify<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.attestation.hash(state);
    }
}

impl<S: Scheme> Nullify<S> {
    /// Signs a nullify vote for the given round.
    pub fn sign<D: Digest>(scheme: &S, round: Round) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(Subject::Nullify { round })?;

        Some(Self { round, attestation })
    }

    /// Verifies the nullify vote against the provided signing scheme.
    ///
    /// This ensures that the nullify signature is valid for the given round.
    pub fn verify<R, D: Digest>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRngCore,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(
            rng,
            Subject::Nullify { round: self.round },
            &self.attestation,
            strategy,
        )
    }

    /// Returns the round associated with this nullify vote.
    pub const fn round(&self) -> Round {
        self.round
    }
}

impl<S: Scheme> Write for Nullify<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.attestation.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Nullify<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.attestation.encode_size()
    }
}

impl<S: Scheme> Read for Nullify<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let attestation = Attestation::read(reader)?;

        Ok(Self { round, attestation })
    }
}

impl<S: Scheme> Attributable for Nullify<S> {
    fn signer(&self) -> Participant {
        self.attestation.signer
    }
}

impl<S: Scheme> Epochable for Nullify<S> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<S: Scheme> Viewable for Nullify<S> {
    fn view(&self) -> View {
        self.round.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme> arbitrary::Arbitrary<'_> for Nullify<S>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let round = Round::arbitrary(u)?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self { round, attestation })
    }
}

/// Nullification certificate recovered from M-quorum (2f+1) nullify votes.
///
/// When a view is nullified, the consensus moves to the next view without finalizing a block.
#[derive(Clone, Debug)]
pub struct Nullification<S: Scheme> {
    /// The round in which this nullification is made.
    pub round: Round,
    /// The recovered certificate for the nullification.
    pub certificate: S::Certificate,
}

impl<S: Scheme> Nullification<S> {
    /// Builds a nullification certificate from nullify votes from the same round.
    ///
    /// Requires M-quorum (2f+1) votes.
    pub fn from_nullifies<'a, I>(scheme: &S, nullifies: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Nullify<S>>,
        I::IntoIter: Send,
    {
        let mut iter = nullifies.into_iter();
        let first = iter.next()?;
        let round = first.round;
        let mut attestations = vec![first.attestation.clone()];

        for nullify in iter {
            if nullify.round != round {
                return None;
            }
            attestations.push(nullify.attestation.clone());
        }

        let certificate = scheme.assemble::<_, M5f1>(attestations, strategy)?;

        Some(Self { round, certificate })
    }

    /// Verifies the nullification certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed round with M-quorum.
    pub fn verify<R: CryptoRngCore, D: Digest>(
        &self,
        rng: &mut R,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_certificate::<_, D, M5f1>(
            rng,
            Subject::Nullify { round: self.round },
            &self.certificate,
            strategy,
        )
    }

    /// Returns the round associated with this nullification.
    pub const fn round(&self) -> Round {
        self.round
    }
}

impl<S: Scheme> PartialEq for Nullification<S> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.certificate == other.certificate
    }
}

impl<S: Scheme> Eq for Nullification<S> {}

impl<S: Scheme> Hash for Nullification<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme> Write for Nullification<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Nullification<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme> Read for Nullification<S> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self { round, certificate })
    }
}

impl<S: Scheme> Epochable for Nullification<S> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<S: Scheme> Viewable for Nullification<S> {
    fn view(&self) -> View {
        self.round.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme> arbitrary::Arbitrary<'_> for Nullification<S>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let round = Round::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self { round, certificate })
    }
}

/// Finalization certificate recovered from L-quorum (n-f) notarize votes.
///
/// Unlike Simplex, Minimmit has no separate finalize vote. Finalization occurs
/// when L-quorum (n-f) notarize votes are collected for the same proposal.
/// When a proposal is finalized, it becomes the canonical block for its view.
///
/// Some signing schemes (like threshold schemes) embed an additional randomness
/// seed in the certificate.
#[derive(Clone, Debug)]
pub struct Finalization<S: Scheme, D: Digest> {
    /// The proposal that has been finalized.
    pub proposal: Proposal<D>,
    /// The recovered certificate for the proposal.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Finalization<S, D> {
    /// Builds a finalization certificate from notarize votes for the same proposal.
    ///
    /// Requires L-quorum (n-f) votes. Note that in Minimmit, finalization uses
    /// the same notarize votes as M-notarization, just with a higher threshold.
    pub fn from_notarizes<'a, I>(scheme: &S, notarizes: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Notarize<S, D>>,
        I::IntoIter: Send,
    {
        let mut iter = notarizes.into_iter();
        let first = iter.next()?;
        let proposal = first.proposal.clone();
        let mut attestations = vec![first.attestation.clone()];

        for notarize in iter {
            if notarize.proposal != proposal {
                return None;
            }
            attestations.push(notarize.attestation.clone());
        }

        let certificate = scheme.assemble::<_, N5f1>(attestations, strategy)?;

        Some(Self {
            proposal,
            certificate,
        })
    }

    /// Verifies the finalization certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed proposal with L-quorum.
    /// Note that the subject is `Subject::Notarize` (not `Subject::Finalize`) because
    /// finalization in Minimmit uses the same vote type as M-notarization.
    pub fn verify<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        scheme: &S,
        strategy: &impl Strategy,
    ) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_certificate::<_, D, N5f1>(
            rng,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.certificate,
            strategy,
        )
    }

    /// Returns the round associated with the finalized proposal.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Finalization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: Scheme, D: Digest> Eq for Finalization<S, D> {}

impl<S: Scheme, D: Digest> Hash for Finalization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Finalization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Finalization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Finalization<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

impl<S: Scheme, D: Digest> Epochable for Finalization<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Finalization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Finalization<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self {
            proposal,
            certificate,
        })
    }
}

/// Evidence of a validator sending conflicting notarize votes for the same view.
///
/// This is Byzantine behavior that proves equivocation (voting for multiple proposals
/// in the same view).
#[derive(Clone, Debug)]
pub struct ConflictingNotarize<S: Scheme, D: Digest> {
    /// First notarize vote.
    pub first: Notarize<S, D>,
    /// Second conflicting notarize vote (different proposal, same view).
    pub second: Notarize<S, D>,
}

impl<S: Scheme, D: Digest> PartialEq for ConflictingNotarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.first == other.first && self.second == other.second
    }
}

impl<S: Scheme, D: Digest> Eq for ConflictingNotarize<S, D> {}

impl<S: Scheme, D: Digest> Hash for ConflictingNotarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.first.hash(state);
        self.second.hash(state);
    }
}

impl<S: Scheme, D: Digest> ConflictingNotarize<S, D> {
    /// Creates a new conflicting notarize evidence from two conflicting notarizes.
    ///
    /// Returns `None` if the notarizes are not for the same view or signer.
    pub fn new(first: Notarize<S, D>, second: Notarize<S, D>) -> Option<Self> {
        if first.view() != second.view() || first.signer() != second.signer() {
            return None;
        }
        Some(Self { first, second })
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRngCore,
        S: scheme::Scheme<D>,
    {
        self.first.verify(rng, scheme, strategy) && self.second.verify(rng, scheme, strategy)
    }
}

impl<S: Scheme, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> Participant {
        self.first.signer()
    }
}

impl<S: Scheme, D: Digest> Epochable for ConflictingNotarize<S, D> {
    fn epoch(&self) -> Epoch {
        self.first.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for ConflictingNotarize<S, D> {
    fn view(&self) -> View {
        self.first.view()
    }
}

impl<S: Scheme, D: Digest> Write for ConflictingNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.first.write(writer);
        self.second.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for ConflictingNotarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let first = Notarize::read(reader)?;
        let second = Notarize::read(reader)?;

        if first.signer() != second.signer() || first.view() != second.view() {
            return Err(Error::Invalid(
                "consensus::minimmit::ConflictingNotarize",
                "invalid conflicting notarize",
            ));
        }

        Ok(Self { first, second })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for ConflictingNotarize<S, D> {
    fn encode_size(&self) -> usize {
        self.first.encode_size() + self.second.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for ConflictingNotarize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let first = Notarize::arbitrary(u)?;
        let second = Notarize::arbitrary(u)?;
        Ok(Self { first, second })
    }
}

/// Consensus activity reported for observability and incentivization.
///
/// Activity represents observable events during consensus, including votes, certificates,
/// and Byzantine behavior evidence.
///
/// Note: Reporting per-validator activity as fault evidence is not safe with threshold
/// cryptography, as any `t` valid partial signatures can be used to forge a partial
/// signature for any player.
#[derive(Clone, Debug)]
pub enum Activity<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A recovered certificate for an M-notarization (2f+1 notarize votes).
    MNotarization(MNotarization<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S>),
    /// A recovered certificate for a nullification (2f+1 nullify votes).
    Nullification(Nullification<S>),
    /// A recovered certificate for a finalization (n-f notarize votes).
    Finalization(Finalization<S, D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior).
    ConflictingNotarize(ConflictingNotarize<S, D>),
}

impl<S: Scheme, D: Digest> PartialEq for Activity<S, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Notarize(a), Self::Notarize(b)) => a == b,
            (Self::MNotarization(a), Self::MNotarization(b)) => a == b,
            (Self::Nullify(a), Self::Nullify(b)) => a == b,
            (Self::Nullification(a), Self::Nullification(b)) => a == b,
            (Self::Finalization(a), Self::Finalization(b)) => a == b,
            (Self::ConflictingNotarize(a), Self::ConflictingNotarize(b)) => a == b,
            _ => false,
        }
    }
}

impl<S: Scheme, D: Digest> Eq for Activity<S, D> {}

impl<S: Scheme, D: Digest> Hash for Activity<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Notarize(v) => {
                0u8.hash(state);
                v.hash(state);
            }
            Self::MNotarization(v) => {
                1u8.hash(state);
                v.hash(state);
            }
            Self::Nullify(v) => {
                2u8.hash(state);
                v.hash(state);
            }
            Self::Nullification(v) => {
                3u8.hash(state);
                v.hash(state);
            }
            Self::Finalization(v) => {
                4u8.hash(state);
                v.hash(state);
            }
            Self::ConflictingNotarize(v) => {
                5u8.hash(state);
                v.hash(state);
            }
        }
    }
}

impl<S: Scheme, D: Digest> Activity<S, D> {
    /// Indicates whether the activity is guaranteed to have been verified by consensus.
    pub const fn verified(&self) -> bool {
        match self {
            Self::Notarize(_)
            | Self::Nullify(_)
            | Self::MNotarization(_)
            | Self::Nullification(_)
            | Self::Finalization(_) => true,
            Self::ConflictingNotarize(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::scheme::ed25519::{fixture, Scheme},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn test_attributable_map_basic() {
        let map: AttributableMap<Notarize<Scheme, Sha256>> = AttributableMap::new(10);

        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_vote_tracker_basic() {
        let tracker: VoteTracker<Scheme, Sha256> = VoteTracker::new(10);

        assert_eq!(tracker.len_notarizes(), 0);
        assert_eq!(tracker.len_nullifies(), 0);
    }

    fn setup_fixture() -> Vec<Scheme> {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, b"minimmit-types", 6);
        schemes
    }

    #[test]
    fn m_notarization_rejects_mixed_proposals_with_same_payload() {
        let schemes = setup_fixture();
        let round = Round::new(Epoch::new(1), View::new(3));
        let payload = Sha256::from([0xAB; 32]);

        let proposal_a = Proposal::new(round, View::new(2), Sha256::from([1; 32]), payload);
        let proposal_b = Proposal::new(round, View::new(2), Sha256::from([2; 32]), payload);

        let votes: Vec<_> = vec![
            Notarize::sign(&schemes[0], proposal_a.clone()).unwrap(),
            Notarize::sign(&schemes[1], proposal_a).unwrap(),
            Notarize::sign(&schemes[2], proposal_b).unwrap(),
        ];

        let m_notarization = MNotarization::from_notarizes(&schemes[0], votes.iter(), &Sequential);
        assert!(m_notarization.is_none());
    }

    #[test]
    fn finalization_rejects_mixed_proposals_with_same_payload() {
        let schemes = setup_fixture();
        let round = Round::new(Epoch::new(1), View::new(3));
        let payload = Sha256::from([0xCD; 32]);

        let proposal_a = Proposal::new(round, View::new(2), Sha256::from([3; 32]), payload);
        let proposal_b = Proposal::new(round, View::new(2), Sha256::from([4; 32]), payload);

        let votes: Vec<_> = vec![
            Notarize::sign(&schemes[0], proposal_a.clone()).unwrap(),
            Notarize::sign(&schemes[1], proposal_a.clone()).unwrap(),
            Notarize::sign(&schemes[2], proposal_a.clone()).unwrap(),
            Notarize::sign(&schemes[3], proposal_a).unwrap(),
            Notarize::sign(&schemes[4], proposal_b).unwrap(),
        ];

        let finalization = Finalization::from_notarizes(&schemes[0], votes.iter(), &Sequential);
        assert!(finalization.is_none());
    }

    #[test]
    fn nullification_rejects_mixed_rounds() {
        let schemes = setup_fixture();
        let round_a = Round::new(Epoch::new(1), View::new(3));
        let round_b = Round::new(Epoch::new(1), View::new(4));

        let votes: Vec<_> = vec![
            Nullify::sign::<Sha256>(&schemes[0], round_a).unwrap(),
            Nullify::sign::<Sha256>(&schemes[1], round_a).unwrap(),
            Nullify::sign::<Sha256>(&schemes[2], round_b).unwrap(),
        ];

        let nullification = Nullification::from_nullifies(&schemes[0], votes.iter(), &Sequential);
        assert!(nullification.is_none());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::minimmit::scheme::bls12381_threshold;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::{
            bls12381::primitives::variant::MinSig, ed25519::PublicKey,
            sha256::Digest as Sha256Digest,
        };

        type Scheme = bls12381_threshold::Scheme<PublicKey, MinSig>;

        commonware_conformance::conformance_tests! {
            CodecConformance<Vote<Scheme, Sha256Digest>>,
            CodecConformance<Certificate<Scheme, Sha256Digest>>,
            CodecConformance<Artifact<Scheme, Sha256Digest>>,
            CodecConformance<Proposal<Sha256Digest>>,
            CodecConformance<Notarize<Scheme, Sha256Digest>>,
            CodecConformance<MNotarization<Scheme, Sha256Digest>>,
            CodecConformance<Nullify<Scheme>>,
            CodecConformance<Nullification<Scheme>>,
            CodecConformance<Finalization<Scheme, Sha256Digest>>,
            CodecConformance<ConflictingNotarize<Scheme, Sha256Digest>>,
        }
    }
}
