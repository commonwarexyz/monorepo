#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, Read};
use commonware_consensus::{
    simplex::{
        scheme::{
            bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519,
            secp256r1, Scheme as SimplexScheme,
        },
        types::{
            Activity, Artifact, Attributable, Backfiller, Certificate, ConflictingFinalize,
            ConflictingNotarize, Context, Finalization, Finalize, Notarization, Notarize,
            Nullification, Nullify, NullifyFinalize, Proposal, Request, Response, Subject, Vote,
            VoteTracker,
        },
    },
    types::View,
    Epochable, Viewable,
};
use commonware_consensus_fuzz::id_mock;
#[cfg(feature = "mocks")]
use commonware_consensus_fuzz::simplex_certificate_mock;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::Scheme as CertificateScheme,
    ed25519::PublicKey,
    sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::hash_map::DefaultHasher,
    fmt::Debug,
    hash::{Hash, Hasher},
};

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type ThresholdSchemeMinPk = bls12381_threshold_vrf::Scheme<PublicKey, MinPk>;
type ThresholdSchemeMinSig = bls12381_threshold_vrf::Scheme<PublicKey, MinSig>;
type Secp256r1Scheme = secp256r1::Scheme<PublicKey>;
type IdScheme = id_mock::Scheme;
#[cfg(feature = "mocks")]
type CertificateMockScheme = simplex_certificate_mock::Scheme<PublicKey, false>;

#[derive(Arbitrary, Debug)]
enum StructuredScheme {
    Ed25519,
    Secp256r1,
    MultisigMinPk,
    MultisigMinSig,
    ThresholdMinPk,
    ThresholdMinSig,
}

#[derive(Arbitrary, Debug)]
enum StructuredKind {
    VoteNotarize,
    VoteNullify,
    VoteFinalize,
    CertificateNotarization,
    CertificateNullification,
    CertificateFinalization,
    ArtifactVoteNotarize,
    ArtifactVoteNullify,
    ArtifactVoteFinalize,
    ArtifactCertificateNotarization,
    ArtifactCertificateNullification,
    ArtifactCertificateFinalization,
    ArtifactCertification,
    ActivityNotarize,
    ActivityNullify,
    ActivityFinalize,
    ActivityNotarization,
    ActivityNullification,
    ActivityFinalization,
    ActivityCertification,
    ActivityConflictingNotarize,
    ActivityConflictingFinalize,
    ActivityNullifyFinalize,
    BackfillerRequest,
    BackfillerResponse,
    Context,
}

#[derive(Arbitrary, Debug)]
enum ArbitraryKind {
    Context,
    Vote,
    Certificate,
    Artifact,
    Backfiller,
    Response,
    Activity,
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    // Ed25519
    Ed25519Vote(Vec<u8>),
    Ed25519Certificate {
        participants: u8,
        data: Vec<u8>,
    },
    Ed25519Backfiller {
        participants: u8,
        data: Vec<u8>,
    },

    // BLS12-381 Multisig MinPk
    MultisigMinPkVote(Vec<u8>),
    MultisigMinPkCertificate {
        participants: u8,
        data: Vec<u8>,
    },

    // BLS12-381 Multisig MinSig
    MultisigMinSigVote(Vec<u8>),
    MultisigMinSigCertificate {
        participants: u8,
        data: Vec<u8>,
    },

    // BLS12-381 Threshold MinPk
    ThresholdMinPkVote(Vec<u8>),
    ThresholdMinPkCertificate(Vec<u8>),

    // BLS12-381 Threshold MinSig
    ThresholdMinSigVote(Vec<u8>),
    ThresholdMinSigCertificate(Vec<u8>),

    // Secp256r1
    Secp256r1Vote(Vec<u8>),
    Secp256r1Certificate {
        participants: u8,
        data: Vec<u8>,
    },

    // ID mock
    IdVote(Vec<u8>),
    IdCertificate {
        participants: u8,
        data: Vec<u8>,
    },

    // Certificate mock
    #[cfg(feature = "mocks")]
    CertificateMockVote(Vec<u8>),
    #[cfg(feature = "mocks")]
    CertificateMockCertificate(Vec<u8>),

    Structured {
        scheme: StructuredScheme,
        kind: StructuredKind,
        seed: u64,
        participants: u8,
        signer: u8,
        proposal: Proposal<sha256::Digest>,
    },

    Arbitrary {
        kind: ArbitraryKind,
        participants: u8,
        data: Vec<u8>,
    },
}

fn roundtrip_vote<S: SimplexScheme<sha256::Digest>>(data: &[u8]) {
    if let Ok(vote) = Vote::<S, sha256::Digest>::decode(data) {
        let encoded = vote.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_certificate<S: SimplexScheme<sha256::Digest>>(
    data: &[u8],
    cfg: &<S::Certificate as Read>::Cfg,
) where
    S::Certificate: Read,
{
    if let Ok(cert) = Certificate::<S, sha256::Digest>::decode_cfg(data, cfg) {
        let encoded = cert.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_decode<T>(data: &[u8], cfg: &T::Cfg)
where
    T: Read + Encode + EncodeSize,
{
    if let Ok(value) = T::decode_cfg(data, cfg) {
        let encoded = value.encode();
        assert_eq!(encoded.len(), value.encode_size());
        assert_eq!(data, encoded.as_ref());
    }
}

fn participant_cfg(participants: u8) -> usize {
    participants.clamp(4, 255) as usize
}

fn structured_participants(participants: u8) -> u32 {
    4 + (participants % 5) as u32
}

fn assert_vote_roundtrip<S>(vote: Vote<S, sha256::Digest>)
where
    S: SimplexScheme<sha256::Digest>,
{
    let encoded = vote.encode();
    assert_eq!(encoded.len(), vote.encode_size());
    let decoded = Vote::<S, sha256::Digest>::decode(encoded.as_ref()).expect("valid vote");
    assert_eq!(decoded.encode(), encoded);
}

fn assert_certificate_roundtrip<S>(scheme: &S, certificate: Certificate<S, sha256::Digest>)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let encoded = certificate.encode();
    assert_eq!(encoded.len(), certificate.encode_size());
    let decoded = Certificate::<S, sha256::Digest>::decode_cfg(
        encoded.as_ref(),
        &scheme.certificate_codec_config(),
    )
    .expect("valid certificate");
    assert_eq!(decoded.encode(), encoded);
}

fn assert_byte_roundtrip<T>(value: T, cfg: &T::Cfg)
where
    T: Read + Encode + EncodeSize,
{
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded.as_ref(), cfg).expect("valid value");
    assert_eq!(decoded.encode(), encoded);
}

fn assert_hash<T: Hash>(value: &T) {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    let _ = hasher.finish();
}

fn assert_structural<T>(value: &T)
where
    T: Clone + Debug + Eq + Hash,
{
    let cloned = value.clone();
    assert_eq!(&cloned, value);
    assert_hash(value);
}

fn assert_activity_roundtrip<S>(scheme: &S, activity: Activity<S, sha256::Digest>)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let cfg = scheme.certificate_codec_config();
    let view = activity.view();
    let epoch = activity.epoch();
    let verified = activity.verified();
    let mut rng = TestRng::new(0);
    assert!(activity.verify(&mut rng, scheme, &Sequential));
    assert_hash(&activity);
    let encoded = activity.encode();
    assert_eq!(encoded.len(), activity.encode_size());
    let decoded =
        Activity::<S, sha256::Digest>::decode_cfg(encoded.as_ref(), &cfg).expect("valid activity");
    assert_eq!(decoded, activity);
    assert_eq!(decoded.verified(), verified);
    assert_eq!(decoded.view(), view);
    assert_eq!(decoded.epoch(), epoch);
    assert_eq!(decoded.encode(), encoded);
}

fn assert_artifact_roundtrip<S>(scheme: &S, artifact: Artifact<S, sha256::Digest>)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let cfg = scheme.certificate_codec_config();
    let view = artifact.view();
    let epoch = artifact.epoch();
    let encoded = artifact.encode();
    assert_eq!(encoded.len(), artifact.encode_size());
    let decoded =
        Artifact::<S, sha256::Digest>::decode_cfg(encoded.as_ref(), &cfg).expect("valid artifact");
    assert_eq!(decoded.view(), view);
    assert_eq!(decoded.epoch(), epoch);
    assert_eq!(decoded.encode(), encoded);
}

fn assert_backfiller_roundtrip<S>(scheme: &S, backfiller: Backfiller<S, sha256::Digest>, max: usize)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let cfg = (max, scheme.certificate_codec_config());
    assert_byte_roundtrip(backfiller, &cfg);
}

fn assert_context_roundtrip(context: Context<sha256::Digest, PublicKey>) {
    let view = context.view();
    let epoch = context.epoch();
    let encoded = context.encode();
    assert_eq!(encoded.len(), context.encode_size());
    let decoded =
        Context::<sha256::Digest, PublicKey>::decode(encoded.as_ref()).expect("valid context");
    assert_eq!(decoded, context);
    assert_eq!(decoded.view(), view);
    assert_eq!(decoded.epoch(), epoch);
    assert_eq!(decoded.encode(), encoded);
}

fn conflicting_proposal(proposal: Proposal<sha256::Digest>) -> Proposal<sha256::Digest> {
    Proposal::new(
        proposal.round,
        View::new(proposal.parent.get().wrapping_add(1)),
        proposal.payload,
    )
}

fn assert_subject_views(proposal: &Proposal<sha256::Digest>) {
    let notarize = Subject::Notarize { proposal };
    let nullify: Subject<'_, sha256::Digest> = Subject::Nullify {
        round: proposal.round,
    };
    let finalize = Subject::Finalize { proposal };
    assert_eq!(notarize.view(), proposal.view());
    assert_eq!(nullify.view(), proposal.view());
    assert_eq!(finalize.view(), proposal.view());
}

fn assert_vote_tracker<S>(schemes: &[S], signer: usize, proposal: &Proposal<sha256::Digest>)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme<PublicKey = PublicKey>,
{
    let Some(notarize) = Notarize::sign(&schemes[signer], proposal.clone()) else {
        return;
    };
    let Some(nullify) = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round) else {
        return;
    };
    let Some(finalize) = Finalize::sign(&schemes[signer], proposal.clone()) else {
        return;
    };

    let mut tracker = VoteTracker::new(schemes.len());
    let signer = notarize.signer();
    assert!(!tracker.has_notarize(signer));
    assert!(!tracker.has_finalize(signer));
    assert!(tracker.insert_notarize(notarize));
    assert!(tracker.insert_nullify(nullify));
    assert!(tracker.insert_finalize(finalize));
    assert!(tracker.has_notarize(signer));
    assert!(tracker.has_finalize(signer));
    assert!(tracker.nullify(signer).is_some());
    assert_eq!(tracker.iter_notarizes().count(), 1);
    assert_eq!(tracker.iter_finalizes().count(), 1);
    tracker.clear_notarizes();
    tracker.clear_finalizes();
    assert!(!tracker.has_notarize(signer));
    assert!(!tracker.has_finalize(signer));
}

fn assert_structured_surface<S>(schemes: &[S], signer: usize, proposal: Proposal<sha256::Digest>)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme<PublicKey = PublicKey>,
{
    assert_subject_views(&proposal);
    assert_vote_tracker(schemes, signer, &proposal);

    let Some(notarize) = Notarize::sign(&schemes[signer], proposal.clone()) else {
        return;
    };
    let Some(nullify) = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round) else {
        return;
    };
    let Some(finalize) = Finalize::sign(&schemes[signer], proposal.clone()) else {
        return;
    };

    assert_vote_roundtrip(Vote::Notarize(notarize.clone()));
    assert_vote_roundtrip(Vote::Nullify(nullify.clone()));
    assert_vote_roundtrip(Vote::Finalize(finalize.clone()));
    assert_artifact_roundtrip(&schemes[0], Vote::Notarize(notarize.clone()).into());
    assert_artifact_roundtrip(&schemes[0], Vote::Nullify(nullify.clone()).into());
    assert_artifact_roundtrip(&schemes[0], Vote::Finalize(finalize.clone()).into());
    assert_activity_roundtrip(&schemes[0], Activity::Notarize(notarize.clone()));
    assert_activity_roundtrip(&schemes[0], Activity::Nullify(nullify.clone()));
    assert_activity_roundtrip(&schemes[0], Activity::Finalize(finalize.clone()));

    let Some(notarizes) = schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let Some(nullifies) = schemes
        .iter()
        .map(|scheme| Nullify::sign::<sha256::Digest>(scheme, proposal.round))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let Some(finalizes) = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let Some(notarization) =
        Notarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential)
    else {
        return;
    };
    let Some(nullification) =
        Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential)
    else {
        return;
    };
    let Some(finalization) =
        Finalization::from_finalizes(&schemes[0], finalizes.iter(), &Sequential)
    else {
        return;
    };

    assert_structural(&notarization);
    assert_structural(&nullification);
    assert_structural(&finalization);
    assert_certificate_roundtrip(&schemes[0], Certificate::Notarization(notarization.clone()));
    assert_certificate_roundtrip(
        &schemes[0],
        Certificate::Nullification(nullification.clone()),
    );
    assert_certificate_roundtrip(&schemes[0], Certificate::Finalization(finalization.clone()));
    assert_artifact_roundtrip(
        &schemes[0],
        Certificate::Notarization(notarization.clone()).into(),
    );
    assert_artifact_roundtrip(
        &schemes[0],
        Certificate::Nullification(nullification.clone()).into(),
    );
    assert_artifact_roundtrip(
        &schemes[0],
        Certificate::Finalization(finalization.clone()).into(),
    );
    assert_activity_roundtrip(&schemes[0], Activity::Notarization(notarization.clone()));
    assert_activity_roundtrip(&schemes[0], Activity::Certification(notarization.clone()));
    assert_activity_roundtrip(&schemes[0], Activity::Nullification(nullification.clone()));
    assert_activity_roundtrip(&schemes[0], Activity::Finalization(finalization));

    let Some(conflicting_notarize) =
        Notarize::sign(&schemes[signer], conflicting_proposal(proposal.clone()))
    else {
        return;
    };
    let Some(conflicting_finalize) =
        Finalize::sign(&schemes[signer], conflicting_proposal(proposal.clone()))
    else {
        return;
    };
    let conflicting_notarize = ConflictingNotarize::new(notarize, conflicting_notarize);
    let conflicting_finalize = ConflictingFinalize::new(finalize.clone(), conflicting_finalize);
    let nullify_finalize = NullifyFinalize::new(nullify, finalize);
    assert_structural(&conflicting_notarize);
    assert_structural(&conflicting_finalize);
    assert_structural(&nullify_finalize);
    assert_activity_roundtrip(
        &schemes[0],
        Activity::ConflictingNotarize(conflicting_notarize),
    );
    assert_activity_roundtrip(
        &schemes[0],
        Activity::ConflictingFinalize(conflicting_finalize),
    );
    assert_activity_roundtrip(&schemes[0], Activity::NullifyFinalize(nullify_finalize));

    let response = Response::new(
        proposal.round.view().get(),
        vec![notarization],
        vec![nullification],
    );
    let mut rng = TestRng::new(0);
    assert!(response.verify(&mut rng, &schemes[0], &Sequential));
    assert_backfiller_roundtrip(&schemes[0], Backfiller::Response(response), 2);

    let request = Request::new(
        proposal.round.view().get(),
        vec![proposal.round.view()],
        vec![proposal.parent],
    );
    assert_backfiller_roundtrip(&schemes[0], Backfiller::Request(request), 2);
}

fn structured<S>(
    schemes: &[S],
    kind: StructuredKind,
    signer: u8,
    proposal: Proposal<sha256::Digest>,
) where
    S: SimplexScheme<sha256::Digest> + CertificateScheme<PublicKey = PublicKey>,
{
    let signer = signer as usize % schemes.len();
    assert_structured_surface(schemes, signer, proposal.clone());
    match kind {
        StructuredKind::VoteNotarize => {
            let Some(vote) = Notarize::sign(&schemes[signer], proposal) else {
                return;
            };
            assert_vote_roundtrip(Vote::Notarize(vote));
        }
        StructuredKind::VoteNullify => {
            let Some(vote) = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round)
            else {
                return;
            };
            assert_vote_roundtrip(Vote::Nullify(vote));
        }
        StructuredKind::VoteFinalize => {
            let Some(vote) = Finalize::sign(&schemes[signer], proposal) else {
                return;
            };
            assert_vote_roundtrip(Vote::Finalize(vote));
        }
        StructuredKind::CertificateNotarization => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Notarization::from_notarizes(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_certificate_roundtrip(&schemes[0], Certificate::Notarization(certificate));
        }
        StructuredKind::CertificateNullification => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Nullify::sign::<sha256::Digest>(scheme, proposal.round))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Nullification::from_nullifies(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_certificate_roundtrip(&schemes[0], Certificate::Nullification(certificate));
        }
        StructuredKind::CertificateFinalization => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Finalization::from_finalizes(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_certificate_roundtrip(&schemes[0], Certificate::Finalization(certificate));
        }
        StructuredKind::ArtifactVoteNotarize => {
            let Some(vote) = Notarize::sign(&schemes[signer], proposal) else {
                return;
            };
            assert_artifact_roundtrip(&schemes[0], Vote::Notarize(vote).into());
        }
        StructuredKind::ArtifactVoteNullify => {
            let Some(vote) = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round)
            else {
                return;
            };
            assert_artifact_roundtrip(&schemes[0], Vote::Nullify(vote).into());
        }
        StructuredKind::ArtifactVoteFinalize => {
            let Some(vote) = Finalize::sign(&schemes[signer], proposal) else {
                return;
            };
            assert_artifact_roundtrip(&schemes[0], Vote::Finalize(vote).into());
        }
        StructuredKind::ArtifactCertificateNotarization => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Notarization::from_notarizes(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_artifact_roundtrip(&schemes[0], Certificate::Notarization(certificate).into());
        }
        StructuredKind::ArtifactCertificateNullification => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Nullify::sign::<sha256::Digest>(scheme, proposal.round))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Nullification::from_nullifies(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_artifact_roundtrip(&schemes[0], Certificate::Nullification(certificate).into());
        }
        StructuredKind::ArtifactCertificateFinalization => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Finalization::from_finalizes(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_artifact_roundtrip(&schemes[0], Certificate::Finalization(certificate).into());
        }
        StructuredKind::ArtifactCertification => {
            assert_artifact_roundtrip(
                &schemes[0],
                Artifact::Certification(proposal.round, signer.is_multiple_of(2)),
            );
        }
        StructuredKind::ActivityNotarize => {
            let Some(vote) = Notarize::sign(&schemes[signer], proposal) else {
                return;
            };
            assert_activity_roundtrip(&schemes[0], Activity::Notarize(vote));
        }
        StructuredKind::ActivityNullify => {
            let Some(vote) = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round)
            else {
                return;
            };
            assert_activity_roundtrip(&schemes[0], Activity::Nullify(vote));
        }
        StructuredKind::ActivityFinalize => {
            let Some(vote) = Finalize::sign(&schemes[signer], proposal) else {
                return;
            };
            assert_activity_roundtrip(&schemes[0], Activity::Finalize(vote));
        }
        StructuredKind::ActivityNotarization | StructuredKind::ActivityCertification => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Notarization::from_notarizes(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            let activity = match kind {
                StructuredKind::ActivityNotarization => Activity::Notarization(certificate),
                StructuredKind::ActivityCertification => Activity::Certification(certificate),
                _ => unreachable!(),
            };
            assert_activity_roundtrip(&schemes[0], activity);
        }
        StructuredKind::ActivityNullification => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Nullify::sign::<sha256::Digest>(scheme, proposal.round))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Nullification::from_nullifies(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_activity_roundtrip(&schemes[0], Activity::Nullification(certificate));
        }
        StructuredKind::ActivityFinalization => {
            let Some(votes) = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(certificate) =
                Finalization::from_finalizes(&schemes[0], votes.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&certificate);
            assert_activity_roundtrip(&schemes[0], Activity::Finalization(certificate));
        }
        StructuredKind::ActivityConflictingNotarize => {
            let Some(vote_1) = Notarize::sign(&schemes[signer], proposal.clone()) else {
                return;
            };
            let Some(vote_2) = Notarize::sign(&schemes[signer], conflicting_proposal(proposal))
            else {
                return;
            };
            let conflict = ConflictingNotarize::new(vote_1, vote_2);
            assert_structural(&conflict);
            assert_activity_roundtrip(&schemes[0], Activity::ConflictingNotarize(conflict));
        }
        StructuredKind::ActivityConflictingFinalize => {
            let Some(vote_1) = Finalize::sign(&schemes[signer], proposal.clone()) else {
                return;
            };
            let Some(vote_2) = Finalize::sign(&schemes[signer], conflicting_proposal(proposal))
            else {
                return;
            };
            let conflict = ConflictingFinalize::new(vote_1, vote_2);
            assert_structural(&conflict);
            assert_activity_roundtrip(&schemes[0], Activity::ConflictingFinalize(conflict));
        }
        StructuredKind::ActivityNullifyFinalize => {
            let Some(nullify) = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round)
            else {
                return;
            };
            let Some(finalize) = Finalize::sign(&schemes[signer], proposal) else {
                return;
            };
            let conflict = NullifyFinalize::new(nullify, finalize);
            assert_structural(&conflict);
            assert_activity_roundtrip(&schemes[0], Activity::NullifyFinalize(conflict));
        }
        StructuredKind::BackfillerRequest => {
            let request = Request::new(
                proposal.round.view().get(),
                vec![proposal.round.view()],
                vec![proposal.parent],
            );
            assert_backfiller_roundtrip(&schemes[0], Backfiller::Request(request), 2);
        }
        StructuredKind::BackfillerResponse => {
            let Some(notarizes) = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(nullifies) = schemes
                .iter()
                .map(|scheme| Nullify::sign::<sha256::Digest>(scheme, proposal.round))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let Some(notarization) =
                Notarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential)
            else {
                return;
            };
            let Some(nullification) =
                Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential)
            else {
                return;
            };
            assert_structural(&notarization);
            assert_structural(&nullification);
            let response = Response::new(
                proposal.round.view().get(),
                vec![notarization],
                vec![nullification],
            );
            assert_backfiller_roundtrip(&schemes[0], Backfiller::Response(response), 2);
        }
        StructuredKind::Context => {
            let Some(leader) = schemes[0].participants().get(signer).cloned() else {
                return;
            };
            assert_context_roundtrip(Context {
                round: proposal.round,
                leader,
                parent: (proposal.parent, proposal.payload),
            });
        }
    }
}

fn assert_arbitrary_byte_roundtrip<T>(u: &mut arbitrary::Unstructured<'_>, cfg: &T::Cfg)
where
    T: for<'a> Arbitrary<'a> + Read + Encode + EncodeSize,
{
    let Ok(value) = T::arbitrary(u) else {
        return;
    };
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    if let Ok(decoded) = T::decode_cfg(encoded.as_ref(), cfg) {
        assert_eq!(decoded.encode(), encoded);
    }
}

fn assert_arbitrary_activity_value(
    activity: Activity<Ed25519Scheme, sha256::Digest>,
    participants: usize,
) {
    assert_hash(&activity);
    let encoded = activity.encode();
    assert_eq!(encoded.len(), activity.encode_size());
    if let Ok(decoded) =
        Activity::<Ed25519Scheme, sha256::Digest>::decode_cfg(encoded.as_ref(), &participants)
    {
        assert_eq!(decoded, activity);
        assert_hash(&decoded);
        assert_eq!(decoded.encode(), encoded);
    }
}

fn assert_arbitrary_activity(data: &[u8], participants: usize, selector: u8) {
    let mut u = arbitrary::Unstructured::new(data);
    let Ok(activity) = Activity::<Ed25519Scheme, sha256::Digest>::arbitrary(&mut u) else {
        let mut tagged = Vec::with_capacity(data.len() + 1);
        tagged.push(selector % 10);
        tagged.extend_from_slice(data);
        let mut u = arbitrary::Unstructured::new(&tagged);
        let Ok(activity) = Activity::<Ed25519Scheme, sha256::Digest>::arbitrary(&mut u) else {
            return;
        };
        assert_arbitrary_activity_value(activity, participants);
        return;
    };
    assert_arbitrary_activity_value(activity, participants);

    let mut tagged = Vec::with_capacity(data.len() + 1);
    tagged.push(selector % 10);
    tagged.extend_from_slice(data);
    let mut u = arbitrary::Unstructured::new(&tagged);
    if let Ok(activity) = Activity::<Ed25519Scheme, sha256::Digest>::arbitrary(&mut u) {
        assert_arbitrary_activity_value(activity, participants);
    };
}

fn arbitrary_case(kind: ArbitraryKind, participants: u8, data: Vec<u8>) {
    let selector = participants;
    let participants = participant_cfg(participants);
    let mut u = arbitrary::Unstructured::new(&data);
    match kind {
        ArbitraryKind::Context => {
            assert_arbitrary_byte_roundtrip::<Context<sha256::Digest, PublicKey>>(&mut u, &());
        }
        ArbitraryKind::Vote => {
            assert_arbitrary_byte_roundtrip::<Vote<Ed25519Scheme, sha256::Digest>>(&mut u, &());
        }
        ArbitraryKind::Certificate => {
            assert_arbitrary_byte_roundtrip::<Certificate<Ed25519Scheme, sha256::Digest>>(
                &mut u,
                &participants,
            );
        }
        ArbitraryKind::Artifact => {
            assert_arbitrary_byte_roundtrip::<Artifact<Ed25519Scheme, sha256::Digest>>(
                &mut u,
                &participants,
            );
        }
        ArbitraryKind::Backfiller => {
            assert_arbitrary_byte_roundtrip::<Backfiller<Ed25519Scheme, sha256::Digest>>(
                &mut u,
                &(participants, participants),
            );
        }
        ArbitraryKind::Response => {
            assert_arbitrary_byte_roundtrip::<Response<Ed25519Scheme, sha256::Digest>>(
                &mut u,
                &(participants, participants),
            );
        }
        ArbitraryKind::Activity => assert_arbitrary_activity(&data, participants, selector),
    }
}

fn structured_case(
    scheme: StructuredScheme,
    kind: StructuredKind,
    seed: u64,
    participants: u8,
    signer: u8,
    proposal: Proposal<sha256::Digest>,
) {
    let mut rng = TestRng::new(seed);
    let n = structured_participants(participants);
    match scheme {
        StructuredScheme::Ed25519 => {
            let fixture = ed25519::fixture(&mut rng, b"simplex_messages", n);
            structured(&fixture.schemes, kind, signer, proposal);
        }
        StructuredScheme::Secp256r1 => {
            let fixture = secp256r1::fixture(&mut rng, b"simplex_messages", n);
            structured(&fixture.schemes, kind, signer, proposal);
        }
        StructuredScheme::MultisigMinPk => {
            let fixture = bls12381_multisig::fixture::<MinPk, _>(&mut rng, b"simplex_messages", n);
            structured(&fixture.schemes, kind, signer, proposal);
        }
        StructuredScheme::MultisigMinSig => {
            let fixture = bls12381_multisig::fixture::<MinSig, _>(&mut rng, b"simplex_messages", n);
            structured(&fixture.schemes, kind, signer, proposal);
        }
        StructuredScheme::ThresholdMinPk => {
            let fixture =
                bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, b"simplex_messages", n);
            structured(&fixture.schemes, kind, signer, proposal);
        }
        StructuredScheme::ThresholdMinSig => {
            let fixture =
                bls12381_threshold_vrf::fixture::<MinSig, _>(&mut rng, b"simplex_messages", n);
            structured(&fixture.schemes, kind, signer, proposal);
        }
    }
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Ed25519Vote(data) => roundtrip_vote::<Ed25519Scheme>(&data),
        FuzzInput::Ed25519Certificate { participants, data } => {
            roundtrip_certificate::<Ed25519Scheme>(&data, &participant_cfg(participants))
        }
        FuzzInput::Ed25519Backfiller { participants, data } => {
            roundtrip_decode::<Backfiller<Ed25519Scheme, sha256::Digest>>(
                &data,
                &(participant_cfg(participants), participant_cfg(participants)),
            )
        }

        FuzzInput::MultisigMinPkVote(data) => roundtrip_vote::<Bls12381MultisigMinPk>(&data),
        FuzzInput::MultisigMinPkCertificate { participants, data } => {
            roundtrip_certificate::<Bls12381MultisigMinPk>(&data, &participant_cfg(participants))
        }

        FuzzInput::MultisigMinSigVote(data) => roundtrip_vote::<Bls12381MultisigMinSig>(&data),
        FuzzInput::MultisigMinSigCertificate { participants, data } => {
            roundtrip_certificate::<Bls12381MultisigMinSig>(&data, &participant_cfg(participants))
        }

        FuzzInput::ThresholdMinPkVote(data) => roundtrip_vote::<ThresholdSchemeMinPk>(&data),
        FuzzInput::ThresholdMinPkCertificate(data) => {
            roundtrip_certificate::<ThresholdSchemeMinPk>(&data, &())
        }

        FuzzInput::ThresholdMinSigVote(data) => roundtrip_vote::<ThresholdSchemeMinSig>(&data),
        FuzzInput::ThresholdMinSigCertificate(data) => {
            roundtrip_certificate::<ThresholdSchemeMinSig>(&data, &())
        }

        FuzzInput::Secp256r1Vote(data) => roundtrip_vote::<Secp256r1Scheme>(&data),
        FuzzInput::Secp256r1Certificate { participants, data } => {
            roundtrip_certificate::<Secp256r1Scheme>(&data, &participant_cfg(participants))
        }

        FuzzInput::IdVote(data) => roundtrip_vote::<IdScheme>(&data),
        FuzzInput::IdCertificate { participants, data } => {
            roundtrip_certificate::<IdScheme>(&data, &participant_cfg(participants))
        }

        #[cfg(feature = "mocks")]
        FuzzInput::CertificateMockVote(data) => roundtrip_vote::<CertificateMockScheme>(&data),
        #[cfg(feature = "mocks")]
        FuzzInput::CertificateMockCertificate(data) => {
            roundtrip_certificate::<CertificateMockScheme>(&data, &())
        }

        FuzzInput::Structured {
            scheme,
            kind,
            seed,
            participants,
            signer,
            proposal,
        } => structured_case(scheme, kind, seed, participants, signer, proposal),

        FuzzInput::Arbitrary {
            kind,
            participants,
            data,
        } => arbitrary_case(kind, participants, data),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
