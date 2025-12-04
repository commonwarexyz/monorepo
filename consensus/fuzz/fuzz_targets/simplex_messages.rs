#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_consensus::simplex::{
    signing_scheme::{
        bls12381_multisig,
        bls12381_threshold::{self},
        ed25519, Scheme,
    },
    types::{
        Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Vote,
    },
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    ed25519::PublicKey,
    sha256,
};
use libfuzzer_sys::fuzz_target;

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type ThresholdSchemeMinPk = bls12381_threshold::Scheme<PublicKey, MinPk>;
type ThresholdSchemeMinSig = bls12381_threshold::Scheme<PublicKey, MinSig>;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    // Ed25519 scheme
    Ed25519Vote(Vec<u8>),
    Ed25519Certificate { participants: u8, data: Vec<u8> },
    Ed25519Notarize(Vec<u8>),
    Ed25519Notarization { participants: u8, data: Vec<u8> },
    Ed25519Nullify(Vec<u8>),
    Ed25519Nullification { participants: u8, data: Vec<u8> },
    Ed25519Finalize(Vec<u8>),
    Ed25519Finalization { participants: u8, data: Vec<u8> },

    // BLS12-381 Multisig MinPk
    MultisigMinPkVote(Vec<u8>),
    MultisigMinPkCertificate { participants: u8, data: Vec<u8> },
    MultisigMinPkNotarize(Vec<u8>),
    MultisigMinPkNotarization { participants: u8, data: Vec<u8> },
    MultisigMinPkNullify(Vec<u8>),
    MultisigMinPkNullification { participants: u8, data: Vec<u8> },
    MultisigMinPkFinalize(Vec<u8>),
    MultisigMinPkFinalization { participants: u8, data: Vec<u8> },

    // BLS12-381 Multisig MinSig
    MultisigMinSigVote(Vec<u8>),
    MultisigMinSigCertificate { participants: u8, data: Vec<u8> },
    MultisigMinSigNotarize(Vec<u8>),
    MultisigMinSigNotarization { participants: u8, data: Vec<u8> },
    MultisigMinSigNullify(Vec<u8>),
    MultisigMinSigNullification { participants: u8, data: Vec<u8> },
    MultisigMinSigFinalize(Vec<u8>),
    MultisigMinSigFinalization { participants: u8, data: Vec<u8> },

    // BLS12-381 Threshold MinPk
    ThresholdMinPkVote(Vec<u8>),
    ThresholdMinPkCertificate(Vec<u8>),
    ThresholdMinPkNotarize(Vec<u8>),
    ThresholdMinPkNotarization(Vec<u8>),
    ThresholdMinPkNullify(Vec<u8>),
    ThresholdMinPkNullification(Vec<u8>),
    ThresholdMinPkFinalize(Vec<u8>),
    ThresholdMinPkFinalization(Vec<u8>),

    // BLS12-381 Threshold MinSig
    ThresholdMinSigVote(Vec<u8>),
    ThresholdMinSigCertificate(Vec<u8>),
    ThresholdMinSigNotarize(Vec<u8>),
    ThresholdMinSigNotarization(Vec<u8>),
    ThresholdMinSigNullify(Vec<u8>),
    ThresholdMinSigNullification(Vec<u8>),
    ThresholdMinSigFinalize(Vec<u8>),
    ThresholdMinSigFinalization(Vec<u8>),
}

fn roundtrip_vote<S: Scheme>(data: &[u8]) {
    if let Ok(vote) = Vote::<S, sha256::Digest>::decode(data) {
        let encoded = vote.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_certificate<S: Scheme>(data: &[u8], cfg: &<S::Certificate as Read>::Cfg)
where
    S::Certificate: Read,
{
    if let Ok(cert) = Certificate::<S, sha256::Digest>::decode_cfg(data, cfg) {
        let encoded = cert.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_notarize<S: Scheme>(data: &[u8]) {
    if let Ok(msg) = Notarize::<S, sha256::Digest>::decode(data) {
        let encoded = msg.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_notarization<S: Scheme>(data: &[u8], cfg: &<S::Certificate as Read>::Cfg)
where
    S::Certificate: Read,
{
    if let Ok(msg) = Notarization::<S, sha256::Digest>::decode_cfg(data, cfg) {
        let encoded = msg.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_nullify<S: Scheme>(data: &[u8]) {
    if let Ok(msg) = Nullify::<S>::decode(data) {
        let encoded = msg.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_nullification<S: Scheme>(data: &[u8], cfg: &<S::Certificate as Read>::Cfg)
where
    S::Certificate: Read,
{
    if let Ok(msg) = Nullification::<S>::decode_cfg(data, cfg) {
        let encoded = msg.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_finalize<S: Scheme>(data: &[u8]) {
    if let Ok(msg) = Finalize::<S, sha256::Digest>::decode(data) {
        let encoded = msg.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_finalization<S: Scheme>(data: &[u8], cfg: &<S::Certificate as Read>::Cfg)
where
    S::Certificate: Read,
{
    if let Ok(msg) = Finalization::<S, sha256::Digest>::decode_cfg(data, cfg) {
        let encoded = msg.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn participant_cfg(participants: u8) -> usize {
    participants.clamp(4, 255) as usize
}

fn fuzz(input: FuzzInput) {
    match input {
        // Ed25519
        FuzzInput::Ed25519Vote(data) => roundtrip_vote::<Ed25519Scheme>(&data),
        FuzzInput::Ed25519Certificate { participants, data } => {
            roundtrip_certificate::<Ed25519Scheme>(&data, &participant_cfg(participants))
        }
        FuzzInput::Ed25519Notarize(data) => roundtrip_notarize::<Ed25519Scheme>(&data),
        FuzzInput::Ed25519Notarization { participants, data } => {
            roundtrip_notarization::<Ed25519Scheme>(&data, &participant_cfg(participants))
        }
        FuzzInput::Ed25519Nullify(data) => roundtrip_nullify::<Ed25519Scheme>(&data),
        FuzzInput::Ed25519Nullification { participants, data } => {
            roundtrip_nullification::<Ed25519Scheme>(&data, &participant_cfg(participants))
        }
        FuzzInput::Ed25519Finalize(data) => roundtrip_finalize::<Ed25519Scheme>(&data),
        FuzzInput::Ed25519Finalization { participants, data } => {
            roundtrip_finalization::<Ed25519Scheme>(&data, &participant_cfg(participants))
        }

        // BLS12-381 Multisig MinPk
        FuzzInput::MultisigMinPkVote(data) => roundtrip_vote::<Bls12381MultisigMinPk>(&data),
        FuzzInput::MultisigMinPkCertificate { participants, data } => {
            roundtrip_certificate::<Bls12381MultisigMinPk>(&data, &participant_cfg(participants))
        }
        FuzzInput::MultisigMinPkNotarize(data) => {
            roundtrip_notarize::<Bls12381MultisigMinPk>(&data)
        }
        FuzzInput::MultisigMinPkNotarization { participants, data } => {
            roundtrip_notarization::<Bls12381MultisigMinPk>(&data, &participant_cfg(participants))
        }
        FuzzInput::MultisigMinPkNullify(data) => roundtrip_nullify::<Bls12381MultisigMinPk>(&data),
        FuzzInput::MultisigMinPkNullification { participants, data } => {
            roundtrip_nullification::<Bls12381MultisigMinPk>(&data, &participant_cfg(participants))
        }
        FuzzInput::MultisigMinPkFinalize(data) => {
            roundtrip_finalize::<Bls12381MultisigMinPk>(&data)
        }
        FuzzInput::MultisigMinPkFinalization { participants, data } => {
            roundtrip_finalization::<Bls12381MultisigMinPk>(&data, &participant_cfg(participants))
        }

        // BLS12-381 Multisig MinSig
        FuzzInput::MultisigMinSigVote(data) => roundtrip_vote::<Bls12381MultisigMinSig>(&data),
        FuzzInput::MultisigMinSigCertificate { participants, data } => {
            roundtrip_certificate::<Bls12381MultisigMinSig>(&data, &participant_cfg(participants))
        }
        FuzzInput::MultisigMinSigNotarize(data) => {
            roundtrip_notarize::<Bls12381MultisigMinSig>(&data)
        }
        FuzzInput::MultisigMinSigNotarization { participants, data } => {
            roundtrip_notarization::<Bls12381MultisigMinSig>(&data, &participant_cfg(participants))
        }
        FuzzInput::MultisigMinSigNullify(data) => {
            roundtrip_nullify::<Bls12381MultisigMinSig>(&data)
        }
        FuzzInput::MultisigMinSigNullification { participants, data } => {
            roundtrip_nullification::<Bls12381MultisigMinSig>(&data, &participant_cfg(participants))
        }
        FuzzInput::MultisigMinSigFinalize(data) => {
            roundtrip_finalize::<Bls12381MultisigMinSig>(&data)
        }
        FuzzInput::MultisigMinSigFinalization { participants, data } => {
            roundtrip_finalization::<Bls12381MultisigMinSig>(&data, &participant_cfg(participants))
        }

        // BLS12-381 Threshold MinPk
        FuzzInput::ThresholdMinPkVote(data) => roundtrip_vote::<ThresholdSchemeMinPk>(&data),
        FuzzInput::ThresholdMinPkCertificate(data) => {
            roundtrip_certificate::<ThresholdSchemeMinPk>(&data, &())
        }
        FuzzInput::ThresholdMinPkNotarize(data) => {
            roundtrip_notarize::<ThresholdSchemeMinPk>(&data)
        }
        FuzzInput::ThresholdMinPkNotarization(data) => {
            roundtrip_notarization::<ThresholdSchemeMinPk>(&data, &())
        }
        FuzzInput::ThresholdMinPkNullify(data) => roundtrip_nullify::<ThresholdSchemeMinPk>(&data),
        FuzzInput::ThresholdMinPkNullification(data) => {
            roundtrip_nullification::<ThresholdSchemeMinPk>(&data, &())
        }
        FuzzInput::ThresholdMinPkFinalize(data) => {
            roundtrip_finalize::<ThresholdSchemeMinPk>(&data)
        }
        FuzzInput::ThresholdMinPkFinalization(data) => {
            roundtrip_finalization::<ThresholdSchemeMinPk>(&data, &())
        }

        // BLS12-381 Threshold MinSig
        FuzzInput::ThresholdMinSigVote(data) => roundtrip_vote::<ThresholdSchemeMinSig>(&data),
        FuzzInput::ThresholdMinSigCertificate(data) => {
            roundtrip_certificate::<ThresholdSchemeMinSig>(&data, &())
        }
        FuzzInput::ThresholdMinSigNotarize(data) => {
            roundtrip_notarize::<ThresholdSchemeMinSig>(&data)
        }
        FuzzInput::ThresholdMinSigNotarization(data) => {
            roundtrip_notarization::<ThresholdSchemeMinSig>(&data, &())
        }
        FuzzInput::ThresholdMinSigNullify(data) => {
            roundtrip_nullify::<ThresholdSchemeMinSig>(&data)
        }
        FuzzInput::ThresholdMinSigNullification(data) => {
            roundtrip_nullification::<ThresholdSchemeMinSig>(&data, &())
        }
        FuzzInput::ThresholdMinSigFinalize(data) => {
            roundtrip_finalize::<ThresholdSchemeMinSig>(&data)
        }
        FuzzInput::ThresholdMinSigFinalization(data) => {
            roundtrip_finalization::<ThresholdSchemeMinSig>(&data, &())
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
