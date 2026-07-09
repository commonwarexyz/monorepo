//! Evidence of Byzantine behavior: pairs of votes that contradict each other.

use super::{
    message::{Attributable, Finalize, Notarize, Nullify, Signed},
    phase::{Phase, Proposal},
};
use crate::{
    simplex::scheme,
    types::{Epoch, Participant, View},
    Epochable, Roundable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;
use std::hash::Hash;

/// Relation satisfied by two votes whose claims contradict each other.
///
/// Two contradictory votes from the same signer in the same round constitute
/// [Conflicting] evidence of Byzantine behavior.
pub trait Contradicts<Rhs = Self> {
    /// Returns whether the two claims contradict each other.
    fn contradicts(&self, other: &Rhs) -> bool;
}

/// Votes of the same phase contradict when they cover different claims (equivocation).
///
/// Restricted to phases whose claim is a [Proposal]: only such claims carry information
/// beyond the round itself, so only they can be equivocated. A nullify's claim is the
/// round, so two nullifies from the same signer in the same round cannot differ and
/// nullify-nullify evidence is unrepresentable.
impl<P, S, D> Contradicts for Signed<P, S, D>
where
    P: Phase<Claim<D> = Proposal<D>>,
    S: Scheme,
    D: Digest,
{
    fn contradicts(&self, other: &Self) -> bool {
        self.claim != other.claim
    }
}

/// A nullify vote contradicts any finalize vote in the same round (a validator should
/// either try to skip a round or finalize a proposal, not both).
impl<S: Scheme, D: Digest> Contradicts<Finalize<S, D>> for Nullify<S, D> {
    fn contradicts(&self, _: &Finalize<S, D>) -> bool {
        true
    }
}

/// Evidence of a Byzantine validator producing two contradictory votes in the same round.
///
/// Same-phase evidence produced by the protocol orders the two votes by claim, so one
/// equivocation has one encoding; the codec accepts either order.
#[derive(Clone, Debug)]
pub struct Conflicting<A, B = A> {
    /// The first conflicting vote.
    first: A,
    /// The second conflicting vote.
    second: B,
}

impl<A: PartialEq, B: PartialEq> PartialEq for Conflicting<A, B> {
    fn eq(&self, other: &Self) -> bool {
        self.first == other.first && self.second == other.second
    }
}

impl<A: Eq, B: Eq> Eq for Conflicting<A, B> {}

impl<A: Hash, B: Hash> Hash for Conflicting<A, B> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.first.hash(state);
        self.second.hash(state);
    }
}

impl<A, B> Conflicting<A, B>
where
    A: Attributable + Epochable + Viewable + Contradicts<B> + Clone,
    B: Attributable + Epochable + Viewable + Clone,
{
    /// Returns whether the two votes constitute conflicting evidence: same round and
    /// signer, contradictory claims.
    fn conflicts(first: &A, second: &B) -> bool {
        first.round() == second.round()
            && first.signer() == second.signer()
            && first.contradicts(second)
    }

    /// Creates conflicting evidence from two votes if they conflict: same round and
    /// signer, contradictory claims.
    pub fn try_new(first: &A, second: &B) -> Option<Self> {
        Self::conflicts(first, second).then(|| Self {
            first: first.clone(),
            second: second.clone(),
        })
    }

    /// Creates new conflicting evidence from two conflicting votes.
    ///
    /// # Panics
    ///
    /// Panics if the two votes do not have the same round and signer, or if their
    /// claims do not contradict each other.
    pub fn new(first: A, second: B) -> Self {
        assert_eq!(first.round(), second.round());
        assert_eq!(first.signer(), second.signer());
        assert!(
            first.contradicts(&second),
            "votes must contradict to constitute conflicting evidence"
        );

        Self { first, second }
    }
}

impl<PA, PB, S, D> Conflicting<Signed<PA, S, D>, Signed<PB, S, D>>
where
    PA: Phase,
    PB: Phase,
    S: Scheme,
    D: Digest,
    Signed<PA, S, D>: Contradicts<Signed<PB, S, D>>,
{
    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        self.first.verify(rng, scheme, strategy) && self.second.verify(rng, scheme, strategy)
    }
}

impl<P, S, D> Conflicting<Signed<P, S, D>>
where
    P: Phase<Claim<D> = Proposal<D>>,
    S: Scheme,
    D: Digest,
{
    /// Creates canonical conflicting evidence from two votes if they conflict: the votes
    /// are ordered by claim so one equivocation has one encoding regardless of arrival
    /// order.
    pub fn try_new_canonical(a: &Signed<P, S, D>, b: &Signed<P, S, D>) -> Option<Self> {
        let (first, second) = if a.claim <= b.claim { (a, b) } else { (b, a) };
        Self::try_new(first, second)
    }
}

impl<A: Attributable, B> Attributable for Conflicting<A, B> {
    fn signer(&self) -> Participant {
        self.first.signer()
    }
}

impl<A: Epochable, B> Epochable for Conflicting<A, B> {
    fn epoch(&self) -> Epoch {
        self.first.epoch()
    }
}

impl<A: Viewable, B> Viewable for Conflicting<A, B> {
    fn view(&self) -> View {
        self.first.view()
    }
}

impl<A: Write, B: Write> Write for Conflicting<A, B> {
    fn write(&self, writer: &mut impl BufMut) {
        self.first.write(writer);
        self.second.write(writer);
    }
}

impl<A, B> Read for Conflicting<A, B>
where
    A: Attributable + Epochable + Viewable + Contradicts<B> + Clone + Read<Cfg = ()>,
    B: Attributable + Epochable + Viewable + Clone + Read<Cfg = ()>,
{
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let first = A::read(reader)?;
        let second = B::read(reader)?;

        if !Self::conflicts(&first, &second) {
            return Err(Error::Invalid(
                "consensus::simplex::Conflicting",
                "invalid conflicting evidence",
            ));
        }

        Ok(Self { first, second })
    }
}

impl<A: EncodeSize, B: EncodeSize> EncodeSize for Conflicting<A, B> {
    fn encode_size(&self) -> usize {
        self.first.encode_size() + self.second.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<A, B> arbitrary::Arbitrary<'_> for Conflicting<A, B>
where
    A: for<'a> arbitrary::Arbitrary<'a>,
    B: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let first = A::arbitrary(u)?;
        let second = B::arbitrary(u)?;
        Ok(Self { first, second })
    }
}

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
pub type ConflictingNotarize<S, D> = Conflicting<Notarize<S, D>>;

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
pub type ConflictingFinalize<S, D> = Conflicting<Finalize<S, D>>;

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
pub type NullifyFinalize<S, D> = Conflicting<Nullify<S, D>, Finalize<S, D>>;
