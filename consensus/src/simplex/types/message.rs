//! Votes and certificates: endorsements of a [Phase]-specific claim, at increasing
//! strength.

use super::phase::{self, Phase, Subject, Tag};
use crate::{
    simplex::scheme::{self, CertificateVerifier},
    types::{Epoch, Participant, Round, View},
    Epochable, Roundable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    certificate::{Attestation, Scheme},
    Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::N3f1;
use rand_core::CryptoRng;
use std::{hash::Hash, iter, slice};

/// Attributable is a trait that provides access to the signer index.
/// This is used to identify which participant signed a given message.
pub trait Attributable {
    /// Returns the index of the signer (validator) who produced this message.
    fn signer(&self) -> Participant;
}

/// A validator's vote over a [Phase]-specific payload.
#[derive(Clone, Debug)]
pub struct Signed<P: Phase<D>, S: Scheme, D: Digest> {
    /// Claim covered by the vote.
    pub claim: P::Claim,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<P: Phase<D>, S: Scheme, D: Digest> Signed<P, S, D> {
    /// Signs a vote over the provided claim.
    pub fn sign(scheme: &S, claim: P::Claim) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(P::subject(&claim))?;

        Some(Self { claim, attestation })
    }

    /// Verifies the vote against the provided signing scheme.
    ///
    /// This ensures that the signature is valid for the claim.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(rng, self.subject(), &self.attestation, strategy)
    }

    /// Returns the domain-separated subject covered by this vote.
    pub fn subject(&self) -> Subject<'_, D> {
        P::subject(&self.claim)
    }

    /// Returns the round associated with this vote.
    pub fn round(&self) -> Round {
        self.claim.round()
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> PartialEq for Signed<P, S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.claim == other.claim && self.attestation == other.attestation
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Eq for Signed<P, S, D> {}

impl<P: Phase<D>, S: Scheme, D: Digest> Hash for Signed<P, S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.claim.hash(state);
        self.attestation.hash(state);
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Write for Signed<P, S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.claim.write(writer);
        self.attestation.write(writer);
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> EncodeSize for Signed<P, S, D> {
    fn encode_size(&self) -> usize {
        self.claim.encode_size() + self.attestation.encode_size()
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Read for Signed<P, S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let claim = P::Claim::read(reader)?;
        let attestation = Attestation::read(reader)?;

        Ok(Self { claim, attestation })
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Attributable for Signed<P, S, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Epochable for Signed<P, S, D> {
    fn epoch(&self) -> Epoch {
        self.claim.epoch()
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Viewable for Signed<P, S, D> {
    fn view(&self) -> View {
        self.claim.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<P: Phase<D>, S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Signed<P, S, D>
where
    P::Claim: for<'a> arbitrary::Arbitrary<'a>,
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let claim = P::Claim::arbitrary(u)?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self { claim, attestation })
    }
}

/// Validator vote that endorses a proposal for notarization.
pub type Notarize<S, D> = Signed<phase::Notarize, S, D>;

/// Validator vote for nullifying the current round, i.e. skip the current round.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
pub type Nullify<S, D> = Signed<phase::Nullify, S, D>;

/// Validator vote to finalize a proposal.
/// This happens after a proposal has been notarized, confirming it as the canonical block
/// for this round.
pub type Finalize<S, D> = Signed<phase::Finalize, S, D>;

/// An aggregated certificate recovered from a quorum of votes over a [Phase]-specific claim.
#[derive(Clone, Debug)]
pub struct Certified<P: Phase<D>, S: Scheme, D: Digest> {
    /// Claim covered by the certificate.
    pub claim: P::Claim,
    /// The recovered certificate for the claim.
    pub certificate: S::Certificate,
}

impl<P: Phase<D>, S: Scheme, D: Digest> Certified<P, S, D> {
    /// Builds a certificate from votes over the same claim.
    pub fn from_votes<'a, I>(scheme: &S, votes: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Signed<P, S, D>>,
        I::IntoIter: Send,
    {
        let mut iter = votes.into_iter().peekable();
        let claim = iter.peek()?.claim.clone();
        let certificate =
            scheme.assemble::<_, N3f1>(iter.map(|v| v.attestation.clone()), strategy)?;

        Some(Self { claim, certificate })
    }

    /// Verifies the certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claim.
    pub fn verify<R: CryptoRng>(
        &self,
        rng: &mut R,
        scheme: &impl CertificateVerifier<D, Certificate = S::Certificate>,
        strategy: &impl Strategy,
    ) -> bool {
        scheme.verify_certificate::<_, D, N3f1>(rng, self.subject(), &self.certificate, strategy)
    }

    /// Returns the domain-separated subject covered by this certificate.
    pub fn subject(&self) -> Subject<'_, D> {
        P::subject(&self.claim)
    }

    /// Returns the round associated with the certified claim.
    pub fn round(&self) -> Round {
        self.claim.round()
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> PartialEq for Certified<P, S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.claim == other.claim && self.certificate == other.certificate
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Eq for Certified<P, S, D> {}

impl<P: Phase<D>, S: Scheme, D: Digest> Hash for Certified<P, S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.claim.hash(state);
        self.certificate.hash(state);
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Write for Certified<P, S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.claim.write(writer);
        self.certificate.write(writer);
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> EncodeSize for Certified<P, S, D> {
    fn encode_size(&self) -> usize {
        self.claim.encode_size() + self.certificate.encode_size()
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Read for Certified<P, S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let claim = P::Claim::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self { claim, certificate })
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Epochable for Certified<P, S, D> {
    fn epoch(&self) -> Epoch {
        self.claim.epoch()
    }
}

impl<P: Phase<D>, S: Scheme, D: Digest> Viewable for Certified<P, S, D> {
    fn view(&self) -> View {
        self.claim.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<P: Phase<D>, S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Certified<P, S, D>
where
    P::Claim: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let claim = P::Claim::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self { claim, certificate })
    }
}

/// Aggregated notarization certificate recovered from notarize votes.
/// When a proposal is notarized, it means at least 2f+1 validators have voted for it.
///
/// Some signing schemes (like [`crate::simplex::scheme::bls12381_threshold::vrf`]) embed an additional
/// randomness seed in the certificate. For threshold signatures, the seed can be accessed
/// via [`crate::simplex::scheme::bls12381_threshold::vrf::Seedable::seed`].
pub type Notarization<S, D> = Certified<phase::Notarize, S, D>;

/// Aggregated nullification certificate recovered from nullify votes.
/// When a view is nullified, the consensus moves to the next view without finalizing a block.
pub type Nullification<S, D> = Certified<phase::Nullify, S, D>;

/// Aggregated finalization certificate recovered from finalize votes.
/// When a proposal is finalized, it becomes the canonical block for its view.
///
/// Some signing schemes (like [`crate::simplex::scheme::bls12381_threshold::vrf`]) embed an additional
/// randomness seed in the certificate. For threshold signatures, the seed can be accessed
/// via [`crate::simplex::scheme::bls12381_threshold::vrf::Seedable::seed`].
pub type Finalization<S, D> = Certified<phase::Finalize, S, D>;

/// Vote represents individual votes ([Notarize], [Nullify], [Finalize]).
#[derive(Clone, Debug, PartialEq)]
pub enum Vote<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S, D>),
    /// A validator's finalize vote over a proposal.
    Finalize(Finalize<S, D>),
}

impl<S: Scheme, D: Digest> Vote<S, D> {
    /// Returns the phase of this vote.
    pub const fn phase(&self) -> Tag {
        match self {
            Self::Notarize(_) => Tag::Notarize,
            Self::Nullify(_) => Tag::Nullify,
            Self::Finalize(_) => Tag::Finalize,
        }
    }
}

impl<S: Scheme, D: Digest> Write for Vote<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        (self.phase() as u8).write(writer);
        match self {
            Self::Notarize(v) => v.write(writer),
            Self::Nullify(v) => v.write(writer),
            Self::Finalize(v) => v.write(writer),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Vote<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Finalize(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Vote<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        let phase = Tag::try_from(tag)
            .map_err(|()| Error::Invalid("consensus::simplex::Vote", "Invalid type"))?;
        Ok(match phase {
            Tag::Notarize => Self::Notarize(Notarize::read(reader)?),
            Tag::Nullify => Self::Nullify(Nullify::read(reader)?),
            Tag::Finalize => Self::Finalize(Finalize::read(reader)?),
        })
    }
}

impl<S: Scheme, D: Digest> Epochable for Vote<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Finalize(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Vote<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Nullify(v) => v.view(),
            Self::Finalize(v) => v.view(),
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
        let tag: u8 = u.int_in_range(0..=2)?;
        Ok(match Tag::ALL[tag as usize] {
            Tag::Notarize => Self::Notarize(Notarize::arbitrary(u)?),
            Tag::Nullify => Self::Nullify(Nullify::arbitrary(u)?),
            Tag::Finalize => Self::Finalize(Finalize::arbitrary(u)?),
        })
    }
}

/// Certificate represents aggregated votes ([Notarization], [Nullification], [Finalization]).
#[derive(Clone, Debug, PartialEq)]
pub enum Certificate<S: Scheme, D: Digest> {
    /// A recovered certificate for a notarization.
    Notarization(Notarization<S, D>),
    /// A recovered certificate for a nullification.
    Nullification(Nullification<S, D>),
    /// A recovered certificate for a finalization.
    Finalization(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Certificate<S, D> {
    /// Returns the phase of this certificate.
    pub const fn phase(&self) -> Tag {
        match self {
            Self::Notarization(_) => Tag::Notarize,
            Self::Nullification(_) => Tag::Nullify,
            Self::Finalization(_) => Tag::Finalize,
        }
    }

    /// Returns the stable trace field value for this certificate's type.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn kind(&self) -> &'static str {
        match self.phase() {
            Tag::Notarize => "notarization",
            Tag::Nullify => "nullification",
            Tag::Finalize => "finalization",
        }
    }

    /// Verifies the certificate against the provided signing scheme.
    pub fn verify<R: CryptoRng>(
        &self,
        rng: &mut R,
        scheme: &impl CertificateVerifier<D, Certificate = S::Certificate>,
        strategy: &impl Strategy,
    ) -> bool {
        match self {
            Self::Notarization(n) => n.verify(rng, scheme, strategy),
            Self::Nullification(n) => n.verify(rng, scheme, strategy),
            Self::Finalization(f) => f.verify(rng, scheme, strategy),
        }
    }
}

impl<S: Scheme, D: Digest> Write for Certificate<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        (self.phase() as u8).write(writer);
        match self {
            Self::Notarization(v) => v.write(writer),
            Self::Nullification(v) => v.write(writer),
            Self::Finalization(v) => v.write(writer),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Certificate<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarization(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Certificate<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        let phase = Tag::try_from(tag)
            .map_err(|()| Error::Invalid("consensus::simplex::Certificate", "Invalid type"))?;
        Ok(match phase {
            Tag::Notarize => Self::Notarization(Notarization::read_cfg(reader, cfg)?),
            Tag::Nullify => Self::Nullification(Nullification::read_cfg(reader, cfg)?),
            Tag::Finalize => Self::Finalization(Finalization::read_cfg(reader, cfg)?),
        })
    }
}

impl<S: Scheme, D: Digest> Epochable for Certificate<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarization(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Certificate<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarization(v) => v.view(),
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
        let tag: u8 = u.int_in_range(0..=2)?;
        Ok(match Tag::ALL[tag as usize] {
            Tag::Notarize => Self::Notarization(Notarization::arbitrary(u)?),
            Tag::Nullify => Self::Nullification(Nullification::arbitrary(u)?),
            Tag::Finalize => Self::Finalization(Finalization::arbitrary(u)?),
        })
    }
}

/// Batch-verifies certificates and returns a per-item result.
///
/// Uses bisection to efficiently identify invalid certificates when batch
/// verification fails.
pub fn verify_certificates<'a, R, S, D>(
    rng: &mut R,
    scheme: &S,
    certificates: &[(Subject<'a, D>, &'a S::Certificate)],
    strategy: &impl Strategy,
) -> Vec<bool>
where
    R: CryptoRng,
    S: CertificateVerifier<D>,
    D: Digest,
{
    scheme.verify_certificates_bisect::<_, D, N3f1>(rng, certificates, strategy)
}

/// A map of [Attributable] items keyed by their signer index.
///
/// The key for each item is automatically inferred from [Attributable::signer()].
/// Each signer can insert at most one item.
pub struct AttributableMap<T: Attributable> {
    data: Vec<Option<T>>,
    added: usize,
}

impl<T: Attributable> AttributableMap<T> {
    /// Creates a new [AttributableMap] with the given number of participants.
    pub fn new(participants: usize) -> Self {
        // `resize_with` avoids requiring `T: Clone` while pre-filling with `None`.
        let mut data = Vec::with_capacity(participants);
        data.resize_with(participants, || None);

        Self { data, added: 0 }
    }

    /// Clears all existing items from the [AttributableMap].
    pub fn clear(&mut self) {
        self.data.fill_with(|| None);
        self.added = 0;
    }

    /// Inserts an item into the map, using [Attributable::signer()] as the key,
    /// if it has not been added yet.
    ///
    /// Returns `true` if the item was inserted, `false` if an item from this
    /// signer already exists or if the signer index is out of bounds.
    pub fn insert(&mut self, item: T) -> bool {
        let index: usize = item.signer().into();
        if index >= self.data.len() {
            return false;
        }
        if self.data[index].is_some() {
            return false;
        }
        self.data[index] = Some(item);
        self.added += 1;
        true
    }

    /// Returns the number of items in the [AttributableMap].
    pub const fn len(&self) -> usize {
        self.added
    }

    /// Returns `true` if the [AttributableMap] is empty.
    pub const fn is_empty(&self) -> bool {
        self.added == 0
    }

    /// Returns a reference to the item associated with the given signer, if present.
    pub fn get(&self, signer: Participant) -> Option<&T> {
        self.data.get(<usize>::from(signer))?.as_ref()
    }

    /// Returns `true` if an item from the given signer is present.
    pub fn contains(&self, signer: Participant) -> bool {
        self.get(signer).is_some()
    }

    /// Returns an iterator over items in the map, ordered by signer index
    /// ([Attributable::signer()]).
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.into_iter()
    }
}

impl<'a, T: Attributable> IntoIterator for &'a AttributableMap<T> {
    type Item = &'a T;
    type IntoIter = iter::FilterMap<slice::Iter<'a, Option<T>>, fn(&'a Option<T>) -> Option<&'a T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.iter().filter_map(Option::as_ref)
    }
}

/// Tracks notarize/nullify/finalize votes for a view.
///
/// Each vote type is stored in its own [`AttributableMap`] so a validator can only
/// contribute one vote per phase. The tracker is reused across rounds/views to keep
/// allocations stable.
pub struct VoteTracker<S: Scheme, D: Digest> {
    /// Per-signer notarize votes keyed by validator index.
    pub notarizes: AttributableMap<Notarize<S, D>>,
    /// Per-signer nullify votes keyed by validator index.
    pub nullifies: AttributableMap<Nullify<S, D>>,
    /// Per-signer finalize votes keyed by validator index.
    ///
    /// Finalize votes include the proposal digest so the entire certificate can be
    /// reconstructed once the quorum threshold is hit.
    pub finalizes: AttributableMap<Finalize<S, D>>,
}

impl<S: Scheme, D: Digest> VoteTracker<S, D> {
    /// Creates a tracker sized for `participants` validators.
    pub fn new(participants: usize) -> Self {
        Self {
            notarizes: AttributableMap::new(participants),
            nullifies: AttributableMap::new(participants),
            finalizes: AttributableMap::new(participants),
        }
    }
}
