//! Types used in [crate::minimmit].

use crate::{
    minimmit::scheme,
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    certificate::{Attestation, Scheme},
    Digest, PublicKey,
};
use rand_core::CryptoRngCore;
use std::{collections::HashMap, fmt::Debug, hash::Hash};

/// Context is a collection of metadata from consensus about a given payload.
/// It provides information about the current epoch/view and the parent payload that new proposals are built on.
#[derive(Clone, Debug)]
pub struct Context<D: Digest, P: PublicKey> {
    /// Current round of consensus.
    pub round: Round,
    /// Leader of the current round.
    pub leader: P,
    /// Parent the payload is built on.
    ///
    /// If there is a gap between the current view and the parent view, the participant
    /// must possess a nullification for each discarded view to safely vote on the proposed
    /// payload (any view without a nullification may eventually be finalized and skipping
    /// it would result in a fork).
    pub parent: (View, D),
}

impl<D: Digest, P: PublicKey> Epochable for Context<D, P> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest, P: PublicKey> Viewable for Context<D, P> {
    fn view(&self) -> View {
        self.round.view()
    }
}

/// Attributable is a trait that provides access to the signer index.
/// This is used to identify which participant signed a given message.
pub trait Attributable {
    /// Returns the index of the signer (validator) who produced this message.
    fn signer(&self) -> u32;
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
        let index = item.signer() as usize;
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
    pub fn get(&self, signer: u32) -> Option<&T> {
        self.data.get(signer as usize)?.as_ref()
    }

    /// Returns an iterator over items in the map, ordered by signer index
    /// ([Attributable::signer()]).
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter().filter_map(|o| o.as_ref())
    }
}

/// Tracks notarize and nullify votes for a view.
///
/// Each vote type is stored in its own [`AttributableMap`] so a validator can only
/// contribute one vote per phase. The tracker is reused across rounds/views to keep
/// allocations stable.
///
/// Unlike simplex, minimmit has no finalize phase - finalization occurs when L notarize
/// votes are collected.
pub struct VoteTracker<S: Scheme, D: Digest> {
    /// Per-signer notarize votes keyed by validator index.
    notarizes: AttributableMap<Notarize<S, D>>,
    /// Per-signer nullify votes keyed by validator index.
    nullifies: AttributableMap<Nullify<S>>,
    /// Tracks which payload each signer notarized for contradiction detection.
    /// Maps signer index to the payload digest they voted for.
    notarize_payloads: HashMap<u32, D>,
}

impl<S: Scheme, D: Digest> VoteTracker<S, D> {
    /// Creates a tracker sized for `participants` validators.
    pub fn new(participants: usize) -> Self {
        Self {
            notarizes: AttributableMap::new(participants),
            nullifies: AttributableMap::new(participants),
            notarize_payloads: HashMap::with_capacity(participants),
        }
    }

    /// Inserts a notarize vote if the signer has not already voted.
    pub fn insert_notarize(&mut self, vote: Notarize<S, D>) -> bool {
        let signer = vote.signer();
        let payload = vote.proposal.payload;
        if self.notarizes.insert(vote) {
            self.notarize_payloads.insert(signer, payload);
            true
        } else {
            false
        }
    }

    /// Inserts a nullify vote if the signer has not already voted.
    pub fn insert_nullify(&mut self, vote: Nullify<S>) -> bool {
        self.nullifies.insert(vote)
    }

    /// Returns the number of notarize votes collected.
    #[allow(clippy::missing_const_for_fn)] // len() is not const for HashMap
    pub fn notarize_count(&self) -> usize {
        self.notarizes.len()
    }

    /// Returns the number of nullify votes collected.
    #[allow(clippy::missing_const_for_fn)] // len() is not const for HashMap
    pub fn nullify_count(&self) -> usize {
        self.nullifies.len()
    }

    /// Returns an iterator over collected notarize votes.
    pub fn notarizes(&self) -> impl Iterator<Item = &Notarize<S, D>> {
        self.notarizes.iter()
    }

    /// Returns an iterator over collected nullify votes.
    pub fn nullifies(&self) -> impl Iterator<Item = &Nullify<S>> {
        self.nullifies.iter()
    }

    /// Checks if the given signer has already submitted a notarize vote.
    pub fn has_notarize(&self, signer: u32) -> bool {
        self.notarizes.get(signer).is_some()
    }

    /// Returns the notarize vote for the given signer, if one exists.
    pub fn get_notarize(&self, signer: u32) -> Option<&Notarize<S, D>> {
        self.notarizes.get(signer)
    }

    /// Checks if the given signer has already submitted a nullify vote.
    pub fn has_nullify(&self, signer: u32) -> bool {
        self.nullifies.get(signer).is_some()
    }

    /// Returns the nullify vote for the given signer, if one exists.
    pub fn get_nullify(&self, signer: u32) -> Option<&Nullify<S>> {
        self.nullifies.get(signer)
    }

    /// Clears all votes, preparing the tracker for a new view.
    pub fn clear(&mut self) {
        self.notarizes.clear();
        self.nullifies.clear();
        self.notarize_payloads.clear();
    }

    /// Counts votes that conflict with the given proposal.
    ///
    /// A conflicting vote is either:
    /// - A nullify vote (always conflicts with any proposal)
    /// - A notarize vote for a different payload
    ///
    /// Used to implement nullify-by-contradiction: if a validator has notarized
    /// a proposal but sees M conflicting votes, they know finalization is impossible
    /// and should broadcast nullify.
    pub fn count_conflicting(&self, our_payload: &D) -> usize {
        let mut count = self.nullifies.len();
        for payload in self.notarize_payloads.values() {
            if payload != our_payload {
                count += 1;
            }
        }
        count
    }

    /// Checks if nullify-by-contradiction should be triggered.
    ///
    /// Returns true if the validator has notarized a proposal but has seen M (2f+1)
    /// conflicting votes, meaning their proposal cannot possibly reach finalization.
    pub fn should_nullify_by_contradiction(
        &self,
        our_payload: Option<&D>,
        m_threshold: usize,
    ) -> bool {
        let Some(payload) = our_payload else {
            return false;
        };
        self.count_conflicting(payload) >= m_threshold
    }
}

/// Identifies the subject of a vote or certificate.
///
/// Implementations use the subject to derive domain-separated message bytes for both
/// individual votes and recovered certificates.
///
/// Unlike simplex, minimmit has no Finalize variant since finalization occurs at L notarizes.
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
/// Unlike simplex, minimmit has no Finalize vote since finalization occurs
/// when L notarize votes are collected.
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
            _ => Err(Error::Invalid(
                "consensus::minimmit::Vote",
                "unknown vote tag",
            )),
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

impl<S: Scheme, D: Digest> Attributable for Vote<S, D> {
    fn signer(&self) -> u32 {
        match self {
            Self::Notarize(v) => v.signer(),
            Self::Nullify(v) => v.signer(),
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
        let choice = u.int_in_range(0..=1)?;
        match choice {
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

/// Certificate represents aggregated votes ([Notarization], [Nullification]).
///
/// A certificate is a proof that M = 2f + 1 validators have voted in agreement.
/// Unlike simplex, minimmit has no Finalization certificate since finalization
/// occurs when L notarize votes are collected.
#[derive(Clone, Debug, PartialEq)]
pub enum Certificate<S: Scheme, D: Digest> {
    /// An aggregated certificate proving M validators notarized a proposal.
    Notarization(Notarization<S, D>),
    /// An aggregated certificate proving M validators nullified a view.
    Nullification(Nullification<S>),
}

impl<S: Scheme, D: Digest> Write for Certificate<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarization(c) => {
                0u8.write(writer);
                c.write(writer);
            }
            Self::Nullification(c) => {
                1u8.write(writer);
                c.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Certificate<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarization(c) => c.encode_size(),
            Self::Nullification(c) => c.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Certificate<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let c = Notarization::read_cfg(reader, cfg)?;
                Ok(Self::Notarization(c))
            }
            1 => {
                let c = Nullification::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(c))
            }
            _ => Err(Error::Invalid(
                "consensus::minimmit::Certificate",
                "unknown certificate tag",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Certificate<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarization(c) => c.epoch(),
            Self::Nullification(c) => c.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Certificate<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarization(c) => c.view(),
            Self::Nullification(c) => c.view(),
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
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => {
                let c = Notarization::arbitrary(u)?;
                Ok(Self::Notarization(c))
            }
            1 => {
                let c = Nullification::arbitrary(u)?;
                Ok(Self::Nullification(c))
            }
            _ => unreachable!(),
        }
    }
}

/// Proof represents either a notarization or nullification for a view.
///
/// A proof is required to advance to the next view. It demonstrates that
/// consensus made progress in the previous view (either notarizing a block
/// or nullifying the view).
pub type Proof<S, D> = Certificate<S, D>;

/// Artifact represents any persistable consensus artifact.
///
/// This is used for write-ahead logging and state recovery.
#[derive(Clone, Debug, PartialEq)]
pub enum Artifact<S: Scheme, D: Digest> {
    /// Individual notarize vote.
    Notarize(Notarize<S, D>),
    /// Aggregated notarization certificate.
    Notarization(Notarization<S, D>),
    /// Individual nullify vote.
    Nullify(Nullify<S>),
    /// Aggregated nullification certificate.
    Nullification(Nullification<S>),
}

impl<S: Scheme, D: Digest> Write for Artifact<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Notarization(c) => {
                1u8.write(writer);
                c.write(writer);
            }
            Self::Nullify(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Self::Nullification(c) => {
                3u8.write(writer);
                c.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Artifact<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Notarization(c) => c.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Nullification(c) => c.encode_size(),
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
                let c = Notarization::read_cfg(reader, cfg)?;
                Ok(Self::Notarization(c))
            }
            2 => {
                let v = Nullify::read(reader)?;
                Ok(Self::Nullify(v))
            }
            3 => {
                let c = Nullification::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(c))
            }
            _ => Err(Error::Invalid(
                "consensus::minimmit::Artifact",
                "unknown artifact tag",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Artifact<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Notarization(c) => c.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Nullification(c) => c.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Artifact<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Notarization(c) => c.view(),
            Self::Nullify(v) => v.view(),
            Self::Nullification(c) => c.view(),
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
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => {
                let v = Notarize::arbitrary(u)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let c = Notarization::arbitrary(u)?;
                Ok(Self::Notarization(c))
            }
            2 => {
                let v = Nullify::arbitrary(u)?;
                Ok(Self::Nullify(v))
            }
            3 => {
                let c = Nullification::arbitrary(u)?;
                Ok(Self::Nullification(c))
            }
            _ => unreachable!(),
        }
    }
}

/// Proposal represents a proposed block in the protocol.
/// It includes the view number, the parent view, and the actual payload (typically a digest of block data).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proposal<D: Digest> {
    /// The round in which this proposal is made
    pub round: Round,
    /// The view of the parent proposal that this one builds upon
    pub parent: View,
    /// The actual payload/content of the proposal (typically a digest of the block data)
    pub payload: D,
}

impl<D: Digest> Proposal<D> {
    /// Creates a new proposal with the specified view, parent view, and payload.
    pub const fn new(round: Round, parent: View, payload: D) -> Self {
        Self {
            round,
            parent,
            payload,
        }
    }
}

impl<D: Digest> Write for Proposal<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.parent.write(writer);
        self.payload.write(writer)
    }
}

impl<D: Digest> Read for Proposal<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let parent = View::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Self {
            round,
            parent,
            payload,
        })
    }
}

impl<D: Digest> EncodeSize for Proposal<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.parent.encode_size() + self.payload.encode_size()
    }
}

impl<D: Digest> Epochable for Proposal<D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for Proposal<D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Proposal<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let round = Round::arbitrary(u)?;
        let parent = View::arbitrary(u)?;
        let payload = D::arbitrary(u)?;
        Ok(Self {
            round,
            parent,
            payload,
        })
    }
}

/// Validator vote that endorses a proposal for notarization.
#[derive(Clone, Debug)]
pub struct Notarize<S: Scheme, D: Digest> {
    /// Proposal being notarized.
    pub proposal: Proposal<D>,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<S: Scheme, D: Digest> Notarize<S, D> {
    /// Signs a notarize vote for the provided proposal.
    pub fn sign(namespace: &[u8], scheme: &S, proposal: Proposal<D>) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(
            namespace,
            Subject::Notarize {
                proposal: &proposal,
            },
        )?;

        Some(Self {
            proposal,
            attestation,
        })
    }

    /// Verifies the notarize vote against the provided signing scheme.
    ///
    /// This ensures that the notarize signature is valid for the claimed proposal.
    pub fn verify(&self, namespace: &[u8], scheme: &S) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<D>(
            namespace,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.attestation,
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
    fn signer(&self) -> u32 {
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

/// Aggregated notarization certificate recovered from notarize votes.
/// When a proposal is notarized, it means at least M = 2f + 1 validators have voted for it.
///
/// Some signing schemes (like [`super::scheme::bls12381_threshold`]) embed an additional
/// randomness seed in the certificate. For threshold signatures, the seed can be accessed
/// via [`super::scheme::bls12381_threshold::Seedable::seed`].
#[derive(Clone, Debug)]
pub struct Notarization<S: Scheme, D: Digest> {
    /// The proposal that has been notarized.
    pub proposal: Proposal<D>,
    /// The recovered certificate for the proposal.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Notarization<S, D> {
    /// Builds a notarization certificate from notarize votes for a specific proposal.
    ///
    /// Only includes votes that match the given proposal. This ensures
    /// the certificate is valid even when Byzantine nodes send conflicting votes.
    pub fn from_notarizes_for_proposal<'a>(
        scheme: &S,
        proposal: Proposal<D>,
        notarizes: impl IntoIterator<Item = &'a Notarize<S, D>>,
    ) -> Option<Self> {
        // Filter to only include votes for the specified proposal
        let certificate =
            scheme.assemble(notarizes.into_iter().filter(|n| n.proposal == proposal).map(|n| n.attestation.clone()))?;

        Some(Self {
            proposal,
            certificate,
        })
    }

    /// Builds a notarization certificate from notarize votes.
    ///
    /// Uses the first vote's proposal and filters all votes to match it.
    /// Prefer `from_notarizes_for_proposal` when the expected proposal is known.
    pub fn from_notarizes<'a>(
        scheme: &S,
        notarizes: impl IntoIterator<Item = &'a Notarize<S, D>>,
    ) -> Option<Self> {
        let mut iter = notarizes.into_iter().peekable();
        let proposal = iter.peek()?.proposal.clone();
        Self::from_notarizes_for_proposal(scheme, proposal, iter)
    }

    /// Verifies the notarization certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed proposal.
    pub fn verify<R: CryptoRngCore>(&self, rng: &mut R, namespace: &[u8], scheme: &S) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_certificate::<_, D>(
            rng,
            namespace,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.certificate,
        )
    }

    /// Returns the round associated with the notarized proposal.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Notarization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: Scheme, D: Digest> Eq for Notarization<S, D> {}

impl<S: Scheme, D: Digest> Hash for Notarization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Notarization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Notarization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Notarization<S, D> {
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

impl<S: Scheme, D: Digest> Epochable for Notarization<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Notarization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Notarization<S, D>
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
/// This is typically used when the leader is unresponsive or fails to propose a valid block,
/// or when nullify-by-contradiction is triggered.
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
    pub fn sign<D: Digest>(namespace: &[u8], scheme: &S, round: Round) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(namespace, Subject::Nullify { round })?;

        Some(Self { round, attestation })
    }

    /// Verifies the nullify vote against the provided signing scheme.
    ///
    /// This ensures that the nullify signature is valid for the given round.
    pub fn verify<D: Digest>(&self, namespace: &[u8], scheme: &S) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<D>(
            namespace,
            Subject::Nullify { round: self.round },
            &self.attestation,
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
    fn signer(&self) -> u32 {
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

/// Aggregated nullification certificate recovered from nullify votes.
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
    pub fn from_nullifies<'a>(
        scheme: &S,
        nullifies: impl IntoIterator<Item = &'a Nullify<S>>,
    ) -> Option<Self> {
        let mut iter = nullifies.into_iter().peekable();
        let round = iter.peek()?.round;
        let certificate = scheme.assemble(iter.map(|n| n.attestation.clone()))?;

        Some(Self { round, certificate })
    }

    /// Verifies the nullification certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed round.
    pub fn verify<R: CryptoRngCore, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        scheme: &S,
    ) -> bool
    where
        S: scheme::Scheme<D>,
    {
        scheme.verify_certificate::<_, D>(
            rng,
            namespace,
            Subject::Nullify { round: self.round },
            &self.certificate,
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

/// Activity types for the reporter.
///
/// Unlike simplex, minimmit has no Finalize/Finalization activity since
/// finalization occurs when L notarize votes are collected.
#[derive(Clone, Debug)]
pub enum Activity<S: Scheme, D: Digest> {
    /// Individual notarize vote.
    Notarize(Notarize<S, D>),
    /// Aggregated notarization certificate (M votes).
    Notarization(Notarization<S, D>),
    /// Individual nullify vote.
    Nullify(Nullify<S>),
    /// Aggregated nullification certificate (M votes).
    Nullification(Nullification<S>),
    /// Conflicting notarize votes from the same signer.
    ConflictingNotarize(ConflictingNotarize<S, D>),
    /// Notarize followed by nullify from the same signer (before observing contradiction).
    NullifyNotarize(NullifyNotarize<S, D>),
}

/// Evidence of a validator sending conflicting notarize votes in the same view.
#[derive(Clone, Debug)]
pub struct ConflictingNotarize<S: Scheme, D: Digest> {
    /// First notarize vote.
    pub first: Notarize<S, D>,
    /// Second notarize vote for a different proposal.
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

impl<S: Scheme, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> u32 {
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

impl<S: Scheme, D: Digest> EncodeSize for ConflictingNotarize<S, D> {
    fn encode_size(&self) -> usize {
        self.first.encode_size() + self.second.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for ConflictingNotarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let first = Notarize::read(reader)?;
        let second = Notarize::read(reader)?;

        if first.signer() != second.signer() || first.round() != second.round() {
            return Err(Error::Invalid(
                "consensus::minimmit::ConflictingNotarize",
                "invalid conflicting notarize",
            ));
        }

        Ok(Self { first, second })
    }
}

/// Evidence of a validator sending notarize then nullify without observing contradiction.
///
/// Note: This is only a fault if the validator nullified before observing M conflicting votes.
/// Nullify-by-contradiction allows sending nullify after notarize when M conflicts are seen.
#[derive(Clone, Debug)]
pub struct NullifyNotarize<S: Scheme, D: Digest> {
    /// The notarize vote.
    pub notarize: Notarize<S, D>,
    /// The nullify vote.
    pub nullify: Nullify<S>,
}

impl<S: Scheme, D: Digest> PartialEq for NullifyNotarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.notarize == other.notarize && self.nullify == other.nullify
    }
}

impl<S: Scheme, D: Digest> Eq for NullifyNotarize<S, D> {}

impl<S: Scheme, D: Digest> Hash for NullifyNotarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.notarize.hash(state);
        self.nullify.hash(state);
    }
}

impl<S: Scheme, D: Digest> Attributable for NullifyNotarize<S, D> {
    fn signer(&self) -> u32 {
        self.notarize.signer()
    }
}

impl<S: Scheme, D: Digest> Epochable for NullifyNotarize<S, D> {
    fn epoch(&self) -> Epoch {
        self.notarize.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for NullifyNotarize<S, D> {
    fn view(&self) -> View {
        self.notarize.view()
    }
}

impl<S: Scheme, D: Digest> Write for NullifyNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.notarize.write(writer);
        self.nullify.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for NullifyNotarize<S, D> {
    fn encode_size(&self) -> usize {
        self.notarize.encode_size() + self.nullify.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for NullifyNotarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let notarize = Notarize::read(reader)?;
        let nullify = Nullify::read(reader)?;

        if notarize.signer() != nullify.signer() || notarize.round() != nullify.round {
            return Err(Error::Invalid(
                "consensus::minimmit::NullifyNotarize",
                "mismatched signatures",
            ));
        }

        Ok(Self { notarize, nullify })
    }
}

impl<S: Scheme, D: Digest> ConflictingNotarize<S, D> {
    /// Verifies both notarize votes.
    pub fn verify(&self, namespace: &[u8], scheme: &S) -> bool
    where
        S: scheme::Scheme<D>,
    {
        self.first.verify(namespace, scheme) && self.second.verify(namespace, scheme)
    }
}

impl<S: Scheme, D: Digest> NullifyNotarize<S, D> {
    /// Verifies both the notarize and nullify votes.
    pub fn verify(&self, namespace: &[u8], scheme: &S) -> bool
    where
        S: scheme::Scheme<D>,
    {
        self.notarize.verify(namespace, scheme) && self.nullify.verify::<D>(namespace, scheme)
    }
}

impl<S: Scheme, D: Digest> Activity<S, D> {
    /// Indicates whether the activity is guaranteed to have been verified by consensus.
    ///
    /// Returns `true` for certificates (which contain quorum proofs that have been
    /// verified during assembly), and `false` for individual votes and fault evidence
    /// (which need explicit verification).
    pub const fn verified(&self) -> bool {
        match self {
            Self::Notarize(_) => false,
            Self::Notarization(_) => true,
            Self::Nullify(_) => false,
            Self::Nullification(_) => true,
            Self::ConflictingNotarize(_) => false,
            Self::NullifyNotarize(_) => false,
        }
    }

    /// Verifies the validity of this activity against the signing scheme.
    ///
    /// This method **always** performs verification regardless of whether the activity has been
    /// previously verified. Callers can use [`Activity::verified`] to check if verification is
    /// necessary before calling this method.
    pub fn verify<R: CryptoRngCore>(&self, rng: &mut R, namespace: &[u8], scheme: &S) -> bool
    where
        S: scheme::Scheme<D>,
    {
        match self {
            Self::Notarize(n) => n.verify(namespace, scheme),
            Self::Notarization(n) => n.verify(rng, namespace, scheme),
            Self::Nullify(n) => n.verify::<D>(namespace, scheme),
            Self::Nullification(n) => n.verify::<_, D>(rng, namespace, scheme),
            Self::ConflictingNotarize(c) => c.verify(namespace, scheme),
            Self::NullifyNotarize(c) => c.verify(namespace, scheme),
        }
    }
}

impl<S: Scheme, D: Digest> PartialEq for Activity<S, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Notarize(a), Self::Notarize(b)) => a == b,
            (Self::Notarization(a), Self::Notarization(b)) => a == b,
            (Self::Nullify(a), Self::Nullify(b)) => a == b,
            (Self::Nullification(a), Self::Nullification(b)) => a == b,
            (Self::ConflictingNotarize(a), Self::ConflictingNotarize(b)) => a == b,
            (Self::NullifyNotarize(a), Self::NullifyNotarize(b)) => a == b,
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
            Self::Notarization(v) => {
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
            Self::ConflictingNotarize(v) => {
                4u8.hash(state);
                v.hash(state);
            }
            Self::NullifyNotarize(v) => {
                5u8.hash(state);
                v.hash(state);
            }
        }
    }
}
