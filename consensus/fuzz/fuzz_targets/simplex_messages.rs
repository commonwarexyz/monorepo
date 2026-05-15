#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, Read};
use commonware_consensus::simplex::{
    scheme::{
        bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519, secp256r1,
        Scheme as SimplexScheme,
    },
    types::{
        Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
        Proposal, Vote,
    },
};
#[cfg(feature = "mocks")]
use commonware_consensus_fuzz::certificate_mock;
use commonware_consensus_fuzz::id_mock;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::Scheme as CertificateScheme,
    ed25519::PublicKey,
    sha256,
};
use commonware_parallel::Sequential;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type ThresholdSchemeMinPk = bls12381_threshold_vrf::Scheme<PublicKey, MinPk>;
type ThresholdSchemeMinSig = bls12381_threshold_vrf::Scheme<PublicKey, MinSig>;
type Secp256r1Scheme = secp256r1::Scheme<PublicKey>;
type IdScheme = id_mock::Scheme;
#[cfg(feature = "mocks")]
type CertificateMockScheme = certificate_mock::Scheme<PublicKey, false>;

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
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    // Ed25519
    Ed25519Vote(Vec<u8>),
    Ed25519Certificate {
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

fn structured<S>(
    schemes: &[S],
    kind: StructuredKind,
    signer: u8,
    proposal: Proposal<sha256::Digest>,
) where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let signer = signer as usize % schemes.len();
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
            assert_certificate_roundtrip(&schemes[0], Certificate::Finalization(certificate));
        }
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
    let mut rng = StdRng::seed_from_u64(seed);
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
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
