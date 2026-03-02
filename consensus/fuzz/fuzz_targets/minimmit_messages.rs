#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_consensus::minimmit::{
    scheme::{bls12381_multisig, bls12381_threshold, ed25519, Scheme},
    types::{Certificate, Vote},
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
    // Ed25519
    Ed25519Vote(Vec<u8>),
    Ed25519Certificate { participants: u8, data: Vec<u8> },

    // BLS12-381 Multisig MinPk
    MultisigMinPkVote(Vec<u8>),
    MultisigMinPkCertificate { participants: u8, data: Vec<u8> },

    // BLS12-381 Multisig MinSig
    MultisigMinSigVote(Vec<u8>),
    MultisigMinSigCertificate { participants: u8, data: Vec<u8> },

    // BLS12-381 Threshold MinPk
    ThresholdMinPkVote(Vec<u8>),
    ThresholdMinPkCertificate { participants: u8, data: Vec<u8> },

    // BLS12-381 Threshold MinSig
    ThresholdMinSigVote(Vec<u8>),
    ThresholdMinSigCertificate { participants: u8, data: Vec<u8> },
}

fn roundtrip_vote<S: Scheme<sha256::Digest>>(data: &[u8]) {
    if let Ok(vote) = Vote::<S, sha256::Digest>::decode(data) {
        let encoded = vote.encode();
        assert_eq!(data, encoded.as_ref());
    }
}

fn roundtrip_certificate<S: Scheme<sha256::Digest>>(
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
    participants.clamp(6, 255) as usize
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
        FuzzInput::ThresholdMinPkCertificate { participants, data } => {
            roundtrip_certificate::<ThresholdSchemeMinPk>(&data, &participant_cfg(participants))
        }

        FuzzInput::ThresholdMinSigVote(data) => roundtrip_vote::<ThresholdSchemeMinSig>(&data),
        FuzzInput::ThresholdMinSigCertificate { participants, data } => {
            roundtrip_certificate::<ThresholdSchemeMinSig>(&data, &participant_cfg(participants))
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
