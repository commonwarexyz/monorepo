//! The vote phase, at the value level ([Tag]) and the type level ([Phase] and its
//! markers).
//!
//! Each [Tag] variant has a corresponding marker type here implementing [Phase], which
//! defines the [Claim] the phase attests and binds a claim into the domain-separated
//! [Subject] covering it. [Signed](super::Signed), [Certified](super::Certified), and
//! [Conflicting](super::Conflicting) are indexed by these markers.

use crate::{
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use std::{fmt::Debug, hash::Hash};

/// A phase's runtime tag.
///
/// [Vote](super::Vote) and [Certificate](super::Certificate) use the
/// discriminants as their wire tags.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// Endorsing a proposal for notarization.
    Notarize = 0,
    /// Skipping the current round.
    Nullify = 1,
    /// Finalizing a proposal.
    Finalize = 2,
}

impl Tag {
    /// All tags, in wire-tag order.
    pub const ALL: [Self; 3] = [Self::Notarize, Self::Nullify, Self::Finalize];
}

const _: () = {
    let mut tag = 0;
    while tag < Tag::ALL.len() {
        assert!(Tag::ALL[tag] as usize == tag);
        tag += 1;
    }
};

impl TryFrom<u8> for Tag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, ()> {
        Self::ALL.get(tag as usize).copied().ok_or(())
    }
}

/// A value a phase can attest: the claim covered by votes and certificates.
pub trait Claim:
    Clone
    + Debug
    + Eq
    + Hash
    + Write
    + EncodeSize
    + Read<Cfg = ()>
    + Epochable
    + Viewable
    + Send
    + Sync
    + 'static
{
}

impl<T> Claim for T where
    T: Clone
        + Debug
        + Eq
        + Hash
        + Write
        + EncodeSize
        + Read<Cfg = ()>
        + Epochable
        + Viewable
        + Send
        + Sync
        + 'static
{
}

/// A type-level vote phase: defines the claim the phase attests and binds a
/// claim into the [Subject] covering it.
///
/// This trait is sealed: the only phases are [Notarize], [Nullify], and [Finalize].
pub trait Phase<D: Digest>: sealed::Sealed + Clone + Debug + Send + Sync + 'static {
    /// The claim attested by votes and certificates of this phase.
    type Claim: Claim;

    /// Binds `claim` into the domain-separated subject covering it.
    fn subject(claim: &Self::Claim) -> Subject<'_, D>;
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Notarize {}
    impl Sealed for super::Nullify {}
    impl Sealed for super::Finalize {}
}

/// Marker for notarize votes and notarization certificates.
#[derive(Clone, Debug)]
pub struct Notarize;

impl<D: Digest> Phase<D> for Notarize {
    type Claim = Proposal<D>;

    fn subject(claim: &Self::Claim) -> Subject<'_, D> {
        Subject::Notarize { proposal: claim }
    }
}

/// Marker for nullify votes and nullification certificates.
#[derive(Clone, Debug)]
pub struct Nullify;

impl<D: Digest> Phase<D> for Nullify {
    type Claim = Round;

    fn subject(claim: &Self::Claim) -> Subject<'_, D> {
        Subject::Nullify { round: *claim }
    }
}

/// Marker for finalize votes and finalization certificates.
#[derive(Clone, Debug)]
pub struct Finalize;

impl<D: Digest> Phase<D> for Finalize {
    type Claim = Proposal<D>;

    fn subject(claim: &Self::Claim) -> Subject<'_, D> {
        Subject::Finalize { proposal: claim }
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

/// Identifies the subject of a vote or certificate.
///
/// Implementations use the subject to derive domain-separated message bytes for both
/// individual votes and recovered certificates.
#[derive(Copy, Clone, Debug)]
pub enum Subject<'a, D: Digest> {
    /// Subject for notarize votes and certificates, carrying the proposal.
    Notarize { proposal: &'a Proposal<D> },
    /// Subject for nullify votes and certificates, scoped to a round.
    Nullify { round: Round },
    /// Subject for finalize votes and certificates, carrying the proposal.
    Finalize { proposal: &'a Proposal<D> },
}

impl<D: Digest> Viewable for Subject<'_, D> {
    fn view(&self) -> View {
        match self {
            Subject::Notarize { proposal } => proposal.view(),
            Subject::Nullify { round } => round.view(),
            Subject::Finalize { proposal } => proposal.view(),
        }
    }
}
