//! Types used in [crate::simplex].
//!
//! Messages are built along two axes: the phase of a vote and the strength of its
//! endorsement.
//!
//! # Phase
//!
//! Validators vote in three phases: notarize, nullify, and finalize. [Tag] identifies a
//! phase at runtime and doubles as the wire tag of [Vote] and [Certificate]. Each phase
//! also has a type-level marker in [phase] implementing [Phase], which defines the
//! [Claim] the phase attests: a [Proposal] for notarize and finalize, the [Round] itself
//! for nullify. [Phase::subject] binds a claim into a domain-separated [Subject], the
//! value actually signed and verified by a [scheme](crate::simplex::scheme).
//!
//! # Endorsement
//!
//! A claim gains weight as validators attest to it:
//!
//! - [Signed] is a single validator's attestation over a claim ([Notarize], [Nullify],
//!   [Finalize]).
//! - [Certified] is a certificate recovered from a quorum of votes over the same claim
//!   ([Notarization], [Nullification], [Finalization]).
//!
//! [Vote] and [Certificate] are the sums of [Signed] and [Certified] over the three
//! phases.
//!
//! # Evidence
//!
//! [Contradicts] relates votes that cannot both be honestly produced by the same signer
//! in the same round, and [Conflicting] pairs two such votes into evidence of Byzantine
//! behavior ([ConflictingNotarize], [ConflictingFinalize], [NullifyFinalize]); its
//! constructors and codec reject pairs that do not conflict. There is no
//! `ConflictingNullify`: a nullify's claim is the round itself, so two nullifies from
//! the same signer in the same round cannot differ. Equivocation is only possible where
//! the claim is a proposal, while a nullify contradicts a finalize by rule.
//!
//! # Channels
//!
//! The remaining types package votes, certificates, and evidence for a particular
//! consumer:
//!
//! - [Vote] and [Certificate] are broadcast between validators.
//! - [Artifact] is journaled to disk for crash recovery.
//! - [Activity] is reported to the application, including evidence.
//! - [Backfiller] ([Request] and [Response]) syncs certificates to lagging validators.

use crate::{
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Digest, PublicKey};

mod channel;
mod evidence;
mod message;
pub mod phase;

pub use channel::{Activity, Artifact, Backfiller, Request, Response};
pub use evidence::{
    Conflicting, ConflictingFinalize, ConflictingNotarize, Contradicts, NullifyFinalize,
};
pub use message::{
    verify_certificates, Attributable, AttributableMap, Certificate, Certified, Finalization,
    Finalize, Notarization, Notarize, Nullification, Nullify, Signed, Vote, VoteTracker,
};
pub use phase::{Claim, Phase, Proposal, Subject, Tag};

/// Context is a collection of metadata from consensus about a given payload.
/// It provides information about the current epoch/view and the parent payload that new proposals are built on.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl<D: Digest, P: PublicKey> Write for Context<D, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.leader.write(buf);
        self.parent.write(buf);
    }
}

impl<D: Digest, P: PublicKey> EncodeSize for Context<D, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.leader.encode_size() + self.parent.encode_size()
    }
}

impl<D: Digest, P: PublicKey> Read for Context<D, P> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let leader = P::read(reader)?;
        let parent = <(View, D)>::read_cfg(reader, &((), ()))?;

        Ok(Self {
            round,
            leader,
            parent,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest, P: PublicKey> arbitrary::Arbitrary<'_> for Context<D, P>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    P: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            round: Round::arbitrary(u)?,
            leader: P::arbitrary(u)?,
            parent: (View::arbitrary(u)?, D::arbitrary(u)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            quorum,
            scheme::{
                bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
                },
                ed25519, secp256r1, Scheme,
            },
        },
        types::Participant,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        sha256::Digest as Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1};
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    /// Generate a fixture using the provided generator function with a specific seed.
    fn setup_seeded<S, F>(n: u32, seed: u64, fixture: F) -> Fixture<S>
    where
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        setup_seeded_ns(n, seed, NAMESPACE, fixture)
    }

    /// Generate a fixture using the provided generator function with a specific seed and namespace.
    fn setup_seeded_ns<S, F>(n: u32, seed: u64, namespace: &[u8], fixture: F) -> Fixture<S>
    where
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = StdRng::seed_from_u64(seed);
        fixture(&mut rng, namespace, n)
    }

    #[test]
    fn test_proposal_encode_decode() {
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let encoded = proposal.encode();
        let decoded = Proposal::<Sha256>::decode(encoded).unwrap();
        assert_eq!(proposal, decoded);
    }

    fn notarize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        let encoded = notarize.encode();
        let decoded = Notarize::decode(encoded).unwrap();

        assert_eq!(notarize, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarize_encode_decode() {
        notarize_encode_decode(ed25519::fixture);
        notarize_encode_decode(secp256r1::fixture);
        notarize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        notarize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        notarize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_votes(&fixture.schemes[0], &notarizes, &Sequential).unwrap();
        let encoded = notarization.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Notarization::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(notarization, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarization_encode_decode() {
        notarization_encode_decode(ed25519::fixture);
        notarization_encode_decode(secp256r1::fixture);
        notarization_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        notarization_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        notarization_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullify_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let nullify = Nullify::<_, Sha256>::sign(&fixture.schemes[0], round).unwrap();
        let encoded = nullify.encode();
        let decoded = Nullify::decode(encoded).unwrap();
        assert_eq!(nullify, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_nullify_encode_decode() {
        nullify_encode_decode(ed25519::fixture);
        nullify_encode_decode(secp256r1::fixture);
        nullify_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        nullify_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        nullify_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        nullify_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullification_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(333), View::new(10));
        let nullifies: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Nullify::<_, Sha256>::sign(scheme, round).unwrap())
            .collect();
        let nullification =
            Nullification::from_votes(&fixture.schemes[0], &nullifies, &Sequential).unwrap();
        let encoded = nullification.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Nullification::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(nullification, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_nullification_encode_decode() {
        nullification_encode_decode(ed25519::fixture);
        nullification_encode_decode(secp256r1::fixture);
        nullification_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        nullification_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        nullification_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullification_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullification_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        nullification_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn finalize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let encoded = finalize.encode();
        let decoded = Finalize::decode(encoded).unwrap();
        assert_eq!(finalize, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_finalize_encode_decode() {
        finalize_encode_decode(ed25519::fixture);
        finalize_encode_decode(secp256r1::fixture);
        finalize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        finalize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        finalize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn finalization_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_votes(&fixture.schemes[0], &finalizes, &Sequential).unwrap();
        let encoded = finalization.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Finalization::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(finalization, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_finalization_encode_decode() {
        finalization_encode_decode(ed25519::fixture);
        finalization_encode_decode(secp256r1::fixture);
        finalization_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        finalization_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        finalization_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalization_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalization_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        finalization_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn backfiller_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let cfg = fixture.schemes[0].certificate_codec_config();
        let request = Request::new(
            1,
            vec![View::new(10), View::new(11)],
            vec![View::new(12), View::new(13)],
        );
        let encoded_request = Backfiller::<S, Sha256>::Request(request.clone()).encode();
        let decoded_request =
            Backfiller::<S, Sha256>::decode_cfg(encoded_request, &(usize::MAX, cfg.clone()))
                .unwrap();
        assert!(matches!(decoded_request, Backfiller::Request(r) if r == request));

        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_votes(&fixture.schemes[0], &notarizes, &Sequential).unwrap();

        let nullifies: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Nullify::<_, Sha256>::sign(scheme, round).unwrap())
            .collect();
        let nullification =
            Nullification::from_votes(&fixture.schemes[0], &nullifies, &Sequential).unwrap();

        let response = Response::<S, Sha256>::new(1, vec![notarization], vec![nullification]);
        let encoded_response = Backfiller::<S, Sha256>::Response(response.clone()).encode();
        let decoded_response =
            Backfiller::<S, Sha256>::decode_cfg(encoded_response, &(usize::MAX, cfg)).unwrap();
        assert!(matches!(decoded_response, Backfiller::Response(r) if r.id == response.id));
    }

    #[test]
    fn test_backfiller_encode_decode() {
        backfiller_encode_decode(ed25519::fixture);
        backfiller_encode_decode(secp256r1::fixture);
        backfiller_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        backfiller_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        backfiller_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        backfiller_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        backfiller_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        backfiller_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    #[test]
    fn test_request_encode_decode() {
        let request = Request::new(
            1,
            vec![View::new(10), View::new(11)],
            vec![View::new(12), View::new(13)],
        );
        let encoded = request.encode();
        let decoded = Request::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(request, decoded);
    }

    fn response_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));

        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_votes(&fixture.schemes[0], &notarizes, &Sequential).unwrap();

        let nullifies: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Nullify::<_, Sha256>::sign(scheme, round).unwrap())
            .collect();
        let nullification =
            Nullification::from_votes(&fixture.schemes[0], &nullifies, &Sequential).unwrap();

        let response = Response::<S, Sha256>::new(1, vec![notarization], vec![nullification]);
        let cfg = fixture.schemes[0].certificate_codec_config();
        let mut decoded =
            Response::<S, Sha256>::decode_cfg(response.encode(), &(usize::MAX, cfg)).unwrap();
        assert_eq!(response.id, decoded.id);
        assert_eq!(response.notarizations.len(), decoded.notarizations.len());
        assert_eq!(response.nullifications.len(), decoded.nullifications.len());

        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));

        decoded.nullifications[0].claim = Round::new(
            decoded.nullifications[0].claim.epoch(),
            decoded.nullifications[0].claim.view().next(),
        );
        assert!(!decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_response_encode_decode() {
        response_encode_decode(ed25519::fixture);
        response_encode_decode(secp256r1::fixture);
        response_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        response_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        response_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        response_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        response_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        response_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn conflicting_notarize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let proposal1 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let proposal2 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(2),
        );
        let notarize1 = Notarize::sign(&fixture.schemes[0], proposal1).unwrap();
        let notarize2 = Notarize::sign(&fixture.schemes[0], proposal2).unwrap();
        let conflicting = ConflictingNotarize::new(notarize1, notarize2);

        let encoded = conflicting.encode();
        let decoded = ConflictingNotarize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_conflicting_notarize_encode_decode() {
        conflicting_notarize_encode_decode(ed25519::fixture);
        conflicting_notarize_encode_decode(secp256r1::fixture);
        conflicting_notarize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_notarize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn conflicting_finalize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let proposal1 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let proposal2 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(2),
        );
        let finalize1 = Finalize::sign(&fixture.schemes[0], proposal1).unwrap();
        let finalize2 = Finalize::sign(&fixture.schemes[0], proposal2).unwrap();
        let conflicting = ConflictingFinalize::new(finalize1, finalize2);

        let encoded = conflicting.encode();
        let decoded = ConflictingFinalize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_conflicting_finalize_encode_decode() {
        conflicting_finalize_encode_decode(ed25519::fixture);
        conflicting_finalize_encode_decode(secp256r1::fixture);
        conflicting_finalize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_finalize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullify_finalize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let nullify = Nullify::<_, Sha256>::sign(&fixture.schemes[0], round).unwrap();
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let conflict = NullifyFinalize::new(nullify, finalize);

        let encoded = conflict.encode();
        let decoded = NullifyFinalize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflict, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_nullify_finalize_encode_decode() {
        nullify_finalize_encode_decode(ed25519::fixture);
        nullify_finalize_encode_decode(secp256r1::fixture);
        nullify_finalize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        nullify_finalize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        nullify_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_finalize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        nullify_finalize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarize_verify_wrong_namespace<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        // Create two fixtures with different namespaces
        let mut rng = test_rng();
        let fixture = setup_seeded_ns(5, 0, NAMESPACE, &f);
        let wrong_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        assert!(notarize.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!notarize.verify(&mut rng, &wrong_fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarize_verify_wrong_namespace() {
        notarize_verify_wrong_namespace(ed25519::fixture);
        notarize_verify_wrong_namespace(secp256r1::fixture);
        notarize_verify_wrong_namespace(bls12381_multisig::fixture::<MinPk, _>);
        notarize_verify_wrong_namespace(bls12381_multisig::fixture::<MinSig, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinPk, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarize_verify_wrong_scheme<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_fixture = setup_seeded(5, 1, &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(2));
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        assert!(notarize.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!notarize.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_notarize_verify_wrong_scheme() {
        notarize_verify_wrong_scheme(ed25519::fixture);
        notarize_verify_wrong_scheme(secp256r1::fixture);
        notarize_verify_wrong_scheme(bls12381_multisig::fixture::<MinPk, _>);
        notarize_verify_wrong_scheme(bls12381_multisig::fixture::<MinSig, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinPk, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_verify_wrong_scheme<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_fixture = setup_seeded(5, 1, &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(3));
        let quorum = N3f1::quorum(fixture.schemes.len()) as usize;
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let notarization = Notarization::from_votes(&fixture.schemes[0], &notarizes, &Sequential)
            .expect("quorum notarization");
        assert!(notarization.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!notarization.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_notarization_verify_wrong_scheme() {
        notarization_verify_wrong_scheme(ed25519::fixture);
        notarization_verify_wrong_scheme(secp256r1::fixture);
        notarization_verify_wrong_scheme(bls12381_multisig::fixture::<MinPk, _>);
        notarization_verify_wrong_scheme(bls12381_multisig::fixture::<MinSig, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_verify_wrong_namespace<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        // Create two fixtures with different namespaces
        let fixture = setup_seeded_ns(5, 0, NAMESPACE, &f);
        let wrong_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let mut rng = test_rng();
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(4));
        let quorum = N3f1::quorum(fixture.schemes.len()) as usize;
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let notarization = Notarization::from_votes(&fixture.schemes[0], &notarizes, &Sequential)
            .expect("quorum notarization");
        assert!(notarization.verify(&mut rng, &fixture.schemes[0], &Sequential));

        assert!(!notarization.verify(&mut rng, &wrong_fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarization_verify_wrong_namespace() {
        notarization_verify_wrong_namespace(ed25519::fixture);
        notarization_verify_wrong_namespace(secp256r1::fixture);
        notarization_verify_wrong_namespace(bls12381_multisig::fixture::<MinPk, _>);
        notarization_verify_wrong_namespace(bls12381_multisig::fixture::<MinSig, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_recover_insufficient_signatures<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let quorum_size = quorum(fixture.schemes.len() as u32) as usize;
        assert!(quorum_size > 1, "test requires quorum larger than one");
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(5));
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum_size - 1)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        assert!(
            Notarization::from_votes(&fixture.schemes[0], &notarizes, &Sequential).is_none(),
            "insufficient votes should not form a notarization"
        );
    }

    #[test]
    fn test_notarization_recover_insufficient_signatures() {
        notarization_recover_insufficient_signatures(ed25519::fixture);
        notarization_recover_insufficient_signatures(secp256r1::fixture);
        notarization_recover_insufficient_signatures(bls12381_multisig::fixture::<MinPk, _>);
        notarization_recover_insufficient_signatures(bls12381_multisig::fixture::<MinSig, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn conflicting_notarize_detection<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_ns_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let wrong_scheme_fixture = setup_seeded(5, 1, &f);

        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal1 = Proposal::new(round, View::new(5), sample_digest(6));
        let proposal2 = Proposal::new(round, View::new(5), sample_digest(7));

        let notarize1 = Notarize::sign(&fixture.schemes[0], proposal1).unwrap();
        let notarize2 = Notarize::sign(&fixture.schemes[0], proposal2).unwrap();
        let conflict = ConflictingNotarize::new(notarize1, notarize2);

        assert!(conflict.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_ns_fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_scheme_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_conflicting_notarize_detection() {
        conflicting_notarize_detection(ed25519::fixture);
        conflicting_notarize_detection(secp256r1::fixture);
        conflicting_notarize_detection(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_notarize_detection(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_notarize_detection(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_notarize_detection(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_notarize_detection(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_notarize_detection(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullify_finalize_detection<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_ns_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let wrong_scheme_fixture = setup_seeded(5, 1, &f);

        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(8));

        let nullify = Nullify::<_, Sha256>::sign(&fixture.schemes[0], round).unwrap();
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let conflict = NullifyFinalize::new(nullify, finalize);

        assert!(conflict.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_ns_fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_scheme_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_nullify_finalize_detection() {
        nullify_finalize_detection(ed25519::fixture);
        nullify_finalize_detection(secp256r1::fixture);
        nullify_finalize_detection(bls12381_multisig::fixture::<MinPk, _>);
        nullify_finalize_detection(bls12381_multisig::fixture::<MinSig, _>);
        nullify_finalize_detection(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_finalize_detection(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_finalize_detection(bls12381_threshold_std::fixture::<MinPk, _>);
        nullify_finalize_detection(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn finalization_verify_wrong_scheme<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_fixture = setup_seeded(5, 1, &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(9));
        let quorum = N3f1::quorum(fixture.schemes.len()) as usize;
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let finalization = Finalization::from_votes(&fixture.schemes[0], &finalizes, &Sequential)
            .expect("quorum finalization");
        assert!(finalization.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!finalization.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_finalization_wrong_scheme() {
        finalization_verify_wrong_scheme(ed25519::fixture);
        finalization_verify_wrong_scheme(secp256r1::fixture);
        finalization_verify_wrong_scheme(bls12381_multisig::fixture::<MinPk, _>);
        finalization_verify_wrong_scheme(bls12381_multisig::fixture::<MinSig, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinPk, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    struct MockAttributable(Participant);

    impl Attributable for MockAttributable {
        fn signer(&self) -> Participant {
            self.0
        }
    }

    #[test]
    fn test_attributable_map() {
        let mut map = AttributableMap::new(5);
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());

        // Test get on empty map
        for i in 0..5 {
            assert!(map.get(Participant::new(i)).is_none());
        }

        assert!(map.insert(MockAttributable(Participant::new(3))));
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(3)));
        assert!(iter.next().is_none());
        drop(iter);

        // Test get on existing item
        assert!(
            matches!(map.get(Participant::new(3)), Some(a) if a.signer() == Participant::new(3))
        );

        assert!(map.insert(MockAttributable(Participant::new(1))));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(1)));
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(3)));
        assert!(iter.next().is_none());
        drop(iter);

        // Test get on both items
        assert!(
            matches!(map.get(Participant::new(1)), Some(a) if a.signer() == Participant::new(1))
        );
        assert!(
            matches!(map.get(Participant::new(3)), Some(a) if a.signer() == Participant::new(3))
        );

        // Test get on non-existing items
        assert!(map.get(Participant::new(0)).is_none());
        assert!(map.get(Participant::new(2)).is_none());
        assert!(map.get(Participant::new(4)).is_none());

        assert!(!map.insert(MockAttributable(Participant::new(3))));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(1)));
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(3)));
        assert!(iter.next().is_none());
        drop(iter);

        // Test out-of-bounds signer indices
        assert!(!map.insert(MockAttributable(Participant::new(5))));
        assert!(!map.insert(MockAttributable(Participant::new(100))));
        assert_eq!(map.len(), 2);

        // Test clear
        map.clear();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert!(map.iter().next().is_none());

        // Verify can insert after clear
        assert!(map.insert(MockAttributable(Participant::new(2))));
        assert_eq!(map.len(), 1);
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(2)));
        assert!(iter.next().is_none());
    }

    #[test]
    #[should_panic(expected = "votes must contradict")]
    fn issue_2944_regression_conflicting_notarize_new() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();
        let _ = ConflictingNotarize::new(notarize.clone(), notarize);
    }

    #[test]
    fn issue_2944_regression_conflicting_notarize_decode() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        // Manually encode two identical notarizes
        let mut buf = Vec::new();
        notarize.write(&mut buf);
        notarize.write(&mut buf);

        // Decoding should fail
        let result = ConflictingNotarize::<ed25519::Scheme, Sha256>::decode(Bytes::from(buf));
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "votes must contradict")]
    fn issue_2944_regression_conflicting_finalize_new() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let _ = ConflictingFinalize::new(finalize.clone(), finalize);
    }

    #[test]
    fn issue_2944_regression_conflicting_finalize_decode() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();

        // Manually encode two identical finalizes
        let mut buf = Vec::new();
        finalize.write(&mut buf);
        finalize.write(&mut buf);

        // Decoding should fail
        let result = ConflictingFinalize::<ed25519::Scheme, Sha256>::decode(Bytes::from(buf));
        assert!(result.is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};

        type Scheme = bls12381_threshold_vrf::Scheme<PublicKey, MinSig>;

        commonware_conformance::conformance_tests! {
            CodecConformance<Vote<Scheme, Sha256Digest>>,
            CodecConformance<Certificate<Scheme, Sha256Digest>>,
            CodecConformance<Artifact<Scheme, Sha256Digest>>,
            CodecConformance<Proposal<Sha256Digest>>,
            CodecConformance<Notarize<Scheme, Sha256Digest>>,
            CodecConformance<Notarization<Scheme, Sha256Digest>>,
            CodecConformance<Nullify<Scheme, Sha256Digest>>,
            CodecConformance<Nullification<Scheme, Sha256Digest>>,
            CodecConformance<Finalize<Scheme, Sha256Digest>>,
            CodecConformance<Finalization<Scheme, Sha256Digest>>,
            CodecConformance<Backfiller<Scheme, Sha256Digest>>,
            CodecConformance<Request>,
            CodecConformance<Response<Scheme, Sha256Digest>>,
            CodecConformance<Activity<Scheme, Sha256Digest>>,
            CodecConformance<ConflictingNotarize<Scheme, Sha256Digest>>,
            CodecConformance<ConflictingFinalize<Scheme, Sha256Digest>>,
            CodecConformance<NullifyFinalize<Scheme, Sha256Digest>>,
            CodecConformance<Context<Sha256Digest, PublicKey>>
        }
    }
}
