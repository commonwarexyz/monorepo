//! Channels that package votes, certificates, and evidence for a consumer: [Artifact]
//! for the journal, [Activity] for the application reporter, and [Backfiller] for
//! certificate sync.

use super::{
    evidence::{ConflictingFinalize, ConflictingNotarize, NullifyFinalize},
    message::{
        Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Vote,
    },
};
use crate::{
    simplex::scheme,
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_parallel::Strategy;
use commonware_utils::N3f1;
use rand_core::CryptoRng;
use std::{collections::HashSet, hash::Hash};

/// Artifact represents all consensus artifacts (votes and certificates) for storage.
#[derive(Clone, Debug, PartialEq)]
pub enum Artifact<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A recovered certificate for a notarization.
    Notarization(Notarization<S, D>),
    /// The local certification outcome (success or failure) for a notarized round.
    ///
    /// Storage-only counterpart of [Activity::Certification], which reports the
    /// certified [Notarization] itself.
    CertificationOutcome(Round, bool),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S, D>),
    /// A recovered certificate for a nullification.
    Nullification(Nullification<S, D>),
    /// A validator's finalize vote over a proposal.
    Finalize(Finalize<S, D>),
    /// A recovered certificate for a finalization.
    Finalization(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Artifact<S, D> {
    /// Returns the codec tag of this variant.
    const fn tag(&self) -> u8 {
        match self {
            Self::Notarize(_) => 0,
            Self::Notarization(_) => 1,
            Self::CertificationOutcome(..) => 2,
            Self::Nullify(_) => 3,
            Self::Nullification(_) => 4,
            Self::Finalize(_) => 5,
            Self::Finalization(_) => 6,
        }
    }
}

impl<S: Scheme, D: Digest> Write for Artifact<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.tag().write(writer);
        match self {
            Self::Notarize(v) => v.write(writer),
            Self::Notarization(v) => v.write(writer),
            Self::CertificationOutcome(r, b) => {
                r.write(writer);
                b.write(writer);
            }
            Self::Nullify(v) => v.write(writer),
            Self::Nullification(v) => v.write(writer),
            Self::Finalize(v) => v.write(writer),
            Self::Finalization(v) => v.write(writer),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Artifact<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Notarization(v) => v.encode_size(),
            Self::CertificationOutcome(r, b) => r.encode_size() + b.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalize(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Artifact<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => Ok(Self::Notarize(Notarize::read(reader)?)),
            1 => Ok(Self::Notarization(Notarization::read_cfg(reader, cfg)?)),
            2 => Ok(Self::CertificationOutcome(
                Round::read(reader)?,
                bool::read(reader)?,
            )),
            3 => Ok(Self::Nullify(Nullify::read(reader)?)),
            4 => Ok(Self::Nullification(Nullification::read_cfg(reader, cfg)?)),
            5 => Ok(Self::Finalize(Finalize::read(reader)?)),
            6 => Ok(Self::Finalization(Finalization::read_cfg(reader, cfg)?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::Artifact",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Artifact<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Notarization(v) => v.epoch(),
            Self::CertificationOutcome(r, _) => r.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalize(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Artifact<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Notarization(v) => v.view(),
            Self::CertificationOutcome(r, _) => r.view(),
            Self::Nullify(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalize(v) => v.view(),
            Self::Finalization(v) => v.view(),
        }
    }
}

impl<S: Scheme, D: Digest> From<Vote<S, D>> for Artifact<S, D> {
    fn from(vote: Vote<S, D>) -> Self {
        match vote {
            Vote::Notarize(v) => Self::Notarize(v),
            Vote::Nullify(v) => Self::Nullify(v),
            Vote::Finalize(v) => Self::Finalize(v),
        }
    }
}

impl<S: Scheme, D: Digest> From<Certificate<S, D>> for Artifact<S, D> {
    fn from(cert: Certificate<S, D>) -> Self {
        match cert {
            Certificate::Notarization(v) => Self::Notarization(v),
            Certificate::Nullification(v) => Self::Nullification(v),
            Certificate::Finalization(v) => Self::Finalization(v),
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
        match u.int_in_range(0..=6)? {
            0 => Ok(Self::Notarize(Notarize::arbitrary(u)?)),
            1 => Ok(Self::Notarization(Notarization::arbitrary(u)?)),
            2 => Ok(Self::CertificationOutcome(
                Round::arbitrary(u)?,
                bool::arbitrary(u)?,
            )),
            3 => Ok(Self::Nullify(Nullify::arbitrary(u)?)),
            4 => Ok(Self::Nullification(Nullification::arbitrary(u)?)),
            5 => Ok(Self::Finalize(Finalize::arbitrary(u)?)),
            6 => Ok(Self::Finalization(Finalization::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

/// Activity represents all possible activities that can occur in the consensus protocol.
/// This includes both regular consensus messages and fault evidence.
///
/// # Verification
///
/// Some activities issued by consensus are not guaranteed to be cryptographically verified (i.e. if not needed
/// to produce a minimum quorum certificate). Use [`Activity::verified`] to check if an activity may not be verified,
/// and [`Activity::verify`] to perform verification.
///
/// # Activity Filtering
///
/// For **non-attributable** schemes like [`crate::simplex::scheme::bls12381_threshold`], exposing
/// per-validator activity as fault evidence is not safe: with threshold cryptography, any `t` valid partial signatures can
/// be used to forge a partial signature for any player.
///
/// Use [`crate::simplex::scheme::reporter::AttributableReporter`] to automatically filter and
/// verify activities based on [`Scheme::is_attributable`].
#[derive(Clone, Debug)]
pub enum Activity<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A recovered certificate for a notarization (scheme-specific).
    Notarization(Notarization<S, D>),
    /// A notarization was locally certified.
    ///
    /// Reported only on success; the journal's [Artifact::CertificationOutcome] records the
    /// outcome as a [Round] and flag.
    Certification(Notarization<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S, D>),
    /// A recovered certificate for a nullification (scheme-specific).
    Nullification(Nullification<S, D>),
    /// A validator's finalize vote over a proposal.
    Finalize(Finalize<S, D>),
    /// A recovered certificate for a finalization (scheme-specific).
    Finalization(Finalization<S, D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior).
    ConflictingNotarize(ConflictingNotarize<S, D>),
    /// Evidence of a validator sending conflicting finalizes (Byzantine behavior).
    ConflictingFinalize(ConflictingFinalize<S, D>),
    /// Evidence of a validator sending both nullify and finalize for the same view (Byzantine behavior).
    NullifyFinalize(NullifyFinalize<S, D>),
}

impl<S: Scheme, D: Digest> PartialEq for Activity<S, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Notarize(a), Self::Notarize(b)) => a == b,
            (Self::Notarization(a), Self::Notarization(b)) => a == b,
            (Self::Certification(a), Self::Certification(b)) => a == b,
            (Self::Nullify(a), Self::Nullify(b)) => a == b,
            (Self::Nullification(a), Self::Nullification(b)) => a == b,
            (Self::Finalize(a), Self::Finalize(b)) => a == b,
            (Self::Finalization(a), Self::Finalization(b)) => a == b,
            (Self::ConflictingNotarize(a), Self::ConflictingNotarize(b)) => a == b,
            (Self::ConflictingFinalize(a), Self::ConflictingFinalize(b)) => a == b,
            (Self::NullifyFinalize(a), Self::NullifyFinalize(b)) => a == b,
            _ => false,
        }
    }
}

impl<S: Scheme, D: Digest> Eq for Activity<S, D> {}

impl<S: Scheme, D: Digest> Hash for Activity<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.tag().hash(state);
        match self {
            Self::Notarize(v) => v.hash(state),
            Self::Notarization(v) => v.hash(state),
            Self::Certification(v) => v.hash(state),
            Self::Nullify(v) => v.hash(state),
            Self::Nullification(v) => v.hash(state),
            Self::Finalize(v) => v.hash(state),
            Self::Finalization(v) => v.hash(state),
            Self::ConflictingNotarize(v) => v.hash(state),
            Self::ConflictingFinalize(v) => v.hash(state),
            Self::NullifyFinalize(v) => v.hash(state),
        }
    }
}

impl<S: Scheme, D: Digest> Activity<S, D> {
    /// Returns the codec tag of this variant.
    const fn tag(&self) -> u8 {
        match self {
            Self::Notarize(_) => 0,
            Self::Notarization(_) => 1,
            Self::Certification(_) => 2,
            Self::Nullify(_) => 3,
            Self::Nullification(_) => 4,
            Self::Finalize(_) => 5,
            Self::Finalization(_) => 6,
            Self::ConflictingNotarize(_) => 7,
            Self::ConflictingFinalize(_) => 8,
            Self::NullifyFinalize(_) => 9,
        }
    }

    /// Indicates whether the activity is guaranteed to have been verified by consensus.
    pub const fn verified(&self) -> bool {
        match self {
            Self::Notarize(_) => false,
            Self::Notarization(_) => true,
            Self::Certification(_) => false,
            Self::Nullify(_) => false,
            Self::Nullification(_) => true,
            Self::Finalize(_) => false,
            Self::Finalization(_) => true,
            Self::ConflictingNotarize(_) => false,
            Self::ConflictingFinalize(_) => false,
            Self::NullifyFinalize(_) => false,
        }
    }

    /// Verifies the validity of this activity against the signing scheme.
    ///
    /// This method **always** performs verification regardless of whether the activity has been
    /// previously verified. Callers can use [`Activity::verified`] to check if verification is
    /// necessary before calling this method.
    pub fn verify<R: CryptoRng>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        S: scheme::Scheme<D>,
    {
        match self {
            Self::Notarize(n) => n.verify(rng, scheme, strategy),
            Self::Notarization(n) => n.verify(rng, scheme, strategy),
            Self::Certification(n) => n.verify(rng, scheme, strategy),
            Self::Nullify(n) => n.verify(rng, scheme, strategy),
            Self::Nullification(n) => n.verify(rng, scheme, strategy),
            Self::Finalize(f) => f.verify(rng, scheme, strategy),
            Self::Finalization(f) => f.verify(rng, scheme, strategy),
            Self::ConflictingNotarize(c) => c.verify(rng, scheme, strategy),
            Self::ConflictingFinalize(c) => c.verify(rng, scheme, strategy),
            Self::NullifyFinalize(c) => c.verify(rng, scheme, strategy),
        }
    }
}

impl<S: Scheme, D: Digest> Write for Activity<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.tag().write(writer);
        match self {
            Self::Notarize(v) => v.write(writer),
            Self::Notarization(v) => v.write(writer),
            Self::Certification(v) => v.write(writer),
            Self::Nullify(v) => v.write(writer),
            Self::Nullification(v) => v.write(writer),
            Self::Finalize(v) => v.write(writer),
            Self::Finalization(v) => v.write(writer),
            Self::ConflictingNotarize(v) => v.write(writer),
            Self::ConflictingFinalize(v) => v.write(writer),
            Self::NullifyFinalize(v) => v.write(writer),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Activity<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Notarization(v) => v.encode_size(),
            Self::Certification(v) => v.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalize(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
            Self::ConflictingNotarize(v) => v.encode_size(),
            Self::ConflictingFinalize(v) => v.encode_size(),
            Self::NullifyFinalize(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Activity<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => Ok(Self::Notarize(Notarize::read(reader)?)),
            1 => Ok(Self::Notarization(Notarization::read_cfg(reader, cfg)?)),
            2 => Ok(Self::Certification(Notarization::read_cfg(reader, cfg)?)),
            3 => Ok(Self::Nullify(Nullify::read(reader)?)),
            4 => Ok(Self::Nullification(Nullification::read_cfg(reader, cfg)?)),
            5 => Ok(Self::Finalize(Finalize::read(reader)?)),
            6 => Ok(Self::Finalization(Finalization::read_cfg(reader, cfg)?)),
            7 => Ok(Self::ConflictingNotarize(ConflictingNotarize::read(
                reader,
            )?)),
            8 => Ok(Self::ConflictingFinalize(ConflictingFinalize::read(
                reader,
            )?)),
            9 => Ok(Self::NullifyFinalize(NullifyFinalize::read(reader)?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Activity<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Notarization(v) => v.epoch(),
            Self::Certification(v) => v.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalize(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
            Self::ConflictingNotarize(v) => v.epoch(),
            Self::ConflictingFinalize(v) => v.epoch(),
            Self::NullifyFinalize(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Activity<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Notarization(v) => v.view(),
            Self::Certification(v) => v.view(),
            Self::Nullify(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalize(v) => v.view(),
            Self::Finalization(v) => v.view(),
            Self::ConflictingNotarize(v) => v.view(),
            Self::ConflictingFinalize(v) => v.view(),
            Self::NullifyFinalize(v) => v.view(),
        }
    }
}

impl<S: Scheme, D: Digest> From<Vote<S, D>> for Activity<S, D> {
    fn from(vote: Vote<S, D>) -> Self {
        match vote {
            Vote::Notarize(v) => Self::Notarize(v),
            Vote::Nullify(v) => Self::Nullify(v),
            Vote::Finalize(v) => Self::Finalize(v),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Activity<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=9)? {
            0 => Ok(Self::Notarize(Notarize::arbitrary(u)?)),
            1 => Ok(Self::Notarization(Notarization::arbitrary(u)?)),
            2 => Ok(Self::Certification(Notarization::arbitrary(u)?)),
            3 => Ok(Self::Nullify(Nullify::arbitrary(u)?)),
            4 => Ok(Self::Nullification(Nullification::arbitrary(u)?)),
            5 => Ok(Self::Finalize(Finalize::arbitrary(u)?)),
            6 => Ok(Self::Finalization(Finalization::arbitrary(u)?)),
            7 => Ok(Self::ConflictingNotarize(ConflictingNotarize::arbitrary(
                u,
            )?)),
            8 => Ok(Self::ConflictingFinalize(ConflictingFinalize::arbitrary(
                u,
            )?)),
            9 => Ok(Self::NullifyFinalize(NullifyFinalize::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<S: Scheme, D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
    Response(Response<S, D>),
}

impl<S: Scheme, D: Digest> Write for Backfiller<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request(request) => {
                0u8.write(writer);
                request.write(writer);
            }
            Self::Response(response) => {
                1u8.write(writer);
                response.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Backfiller<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request(v) => v.encode_size(),
            Self::Response(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Backfiller<S, D> {
    type Cfg = (usize, <S::Certificate as Read>::Cfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => Ok(Self::Request(Request::read_cfg(reader, &cfg.0)?)),
            1 => Ok(Self::Response(Response::read_cfg(reader, cfg)?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::Backfiller",
                "Invalid type",
            )),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Backfiller<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=1)? {
            0 => Ok(Self::Request(Request::arbitrary(u)?)),
            1 => Ok(Self::Response(Response::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

/// Request is a message to request missing notarizations and nullifications.
/// This is used by validators who need to catch up with the consensus state.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Request {
    /// Unique identifier for this request (used to match responses)
    pub id: u64,
    /// Views for which notarizations are requested
    pub notarizations: Vec<View>,
    /// Views for which nullifications are requested
    pub nullifications: Vec<View>,
}

impl Request {
    /// Creates a new request for missing notarizations and nullifications.
    pub const fn new(id: u64, notarizations: Vec<View>, nullifications: Vec<View>) -> Self {
        Self {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl Write for Request {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

/// Ensures every view yielded by `views` is distinct.
fn distinct_views(
    views: impl IntoIterator<Item = View>,
    context: &'static str,
    message: &'static str,
) -> Result<(), Error> {
    let mut seen = HashSet::new();
    for view in views {
        if !seen.insert(view) {
            return Err(Error::Invalid(context, message));
        }
    }
    Ok(())
}

impl Read for Request {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let notarizations = Vec::<View>::read_range(reader, ..=*max_len)?;
        distinct_views(
            notarizations.iter().copied(),
            "consensus::simplex::Request",
            "Duplicate notarization",
        )?;
        let remaining = max_len - notarizations.len();
        let nullifications = Vec::<View>::read_range(reader, ..=remaining)?;
        distinct_views(
            nullifications.iter().copied(),
            "consensus::simplex::Request",
            "Duplicate nullification",
        )?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Response is a message containing the requested notarizations and nullifications.
/// This is sent in response to a Request message.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<S: Scheme, D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<S, D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification<S, D>>,
}

impl<S: Scheme, D: Digest> Response<S, D> {
    /// Creates a new response with the given id, notarizations, and nullifications.
    pub const fn new(
        id: u64,
        notarizations: Vec<Notarization<S, D>>,
        nullifications: Vec<Nullification<S, D>>,
    ) -> Self {
        Self {
            id,
            notarizations,
            nullifications,
        }
    }

    /// Verifies the certificates contained in this response against the signing scheme.
    pub fn verify<R: CryptoRng>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        S: scheme::Scheme<D>,
    {
        // Prepare to verify
        if self.notarizations.is_empty() && self.nullifications.is_empty() {
            return true;
        }

        let notarizations = self
            .notarizations
            .iter()
            .map(|notarization| (notarization.subject(), &notarization.certificate));

        let nullifications = self
            .nullifications
            .iter()
            .map(|nullification| (nullification.subject(), &nullification.certificate));

        scheme.verify_certificates::<_, D, _, N3f1>(
            rng,
            notarizations.chain(nullifications),
            strategy,
        )
    }
}

impl<S: Scheme, D: Digest> Write for Response<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Response<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Response<S, D> {
    type Cfg = (usize, <S::Certificate as Read>::Cfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let (max_len, certificate_cfg) = cfg;
        let id = UInt::read(reader)?.into();
        let notarizations = Vec::<Notarization<S, D>>::read_cfg(
            reader,
            &((..=*max_len).into(), certificate_cfg.clone()),
        )?;
        distinct_views(
            notarizations.iter().map(Viewable::view),
            "consensus::simplex::Response",
            "Duplicate notarization",
        )?;
        let remaining = max_len - notarizations.len();
        let nullifications = Vec::<Nullification<S, D>>::read_cfg(
            reader,
            &((..=remaining).into(), certificate_cfg.clone()),
        )?;
        distinct_views(
            nullifications.iter().map(Viewable::view),
            "consensus::simplex::Response",
            "Duplicate nullification",
        )?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Response<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let id = u.arbitrary()?;
        let notarizations = u.arbitrary()?;
        let nullifications = u.arbitrary()?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}
