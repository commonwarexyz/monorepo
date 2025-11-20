#![no_main]
use arbitrary::Arbitrary;
use commonware_codec::{Read, ReadExt};
use commonware_consensus::simplex::{
    signing_scheme::{
        bls12381_multisig,
        bls12381_threshold::{self},
        ed25519, Scheme,
    },
    types::{Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Voter},
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
enum FuzzScheme {
    Ed25519,
    Bls12381MultisigMinPk,
    Bls12381MultisigMinSig,
    Bls12381ThresholdMinPk,
    Bls12381ThresholdMinSig,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    participants_count: u8,
    scheme: FuzzScheme,
    message_bytes: Vec<u8>,
}

fn fuzz_with_participant_count<S: Scheme>(input: &FuzzInput)
where
    S::Certificate: Read<Cfg = usize>,
{
    let participants_count = input.participants_count.clamp(4, 255) as usize;

    let cert_cfg = participants_count;

    let mut reader = &input.message_bytes[..];
    let _ = Voter::<S, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Notarize::<S, sha256::Digest>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Notarization::<S, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Nullify::<S>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Nullification::<S>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Finalize::<S, sha256::Digest>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Finalization::<S, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);
}

fn fuzz_threshold_minpk(input: &FuzzInput) {
    let cert_cfg = ();

    let mut reader = &input.message_bytes[..];
    let _ = Voter::<ThresholdSchemeMinPk, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Notarize::<ThresholdSchemeMinPk, sha256::Digest>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Notarization::<ThresholdSchemeMinPk, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Nullify::<ThresholdSchemeMinPk>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Nullification::<ThresholdSchemeMinPk>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Finalize::<ThresholdSchemeMinPk, sha256::Digest>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Finalization::<ThresholdSchemeMinPk, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);
}

fn fuzz_threshold_minsig(input: &FuzzInput) {
    let cert_cfg = ();

    let mut reader = &input.message_bytes[..];
    let _ = Voter::<ThresholdSchemeMinSig, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Notarize::<ThresholdSchemeMinSig, sha256::Digest>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Notarization::<ThresholdSchemeMinSig, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Nullify::<ThresholdSchemeMinSig>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Nullification::<ThresholdSchemeMinSig>::read_cfg(&mut reader, &cert_cfg);

    let mut reader = &input.message_bytes[..];
    let _ = Finalize::<ThresholdSchemeMinSig, sha256::Digest>::read(&mut reader);

    let mut reader = &input.message_bytes[..];
    let _ = Finalization::<ThresholdSchemeMinSig, sha256::Digest>::read_cfg(&mut reader, &cert_cfg);
}

fuzz_target!(|input: FuzzInput| {
    match input.scheme {
        FuzzScheme::Ed25519 => {
            fuzz_with_participant_count::<Ed25519Scheme>(&input);
        }
        FuzzScheme::Bls12381MultisigMinPk => {
            fuzz_with_participant_count::<Bls12381MultisigMinPk>(&input);
        }
        FuzzScheme::Bls12381MultisigMinSig => {
            fuzz_with_participant_count::<Bls12381MultisigMinSig>(&input);
        }
        FuzzScheme::Bls12381ThresholdMinPk => {
            fuzz_threshold_minpk(&input);
        }
        FuzzScheme::Bls12381ThresholdMinSig => {
            fuzz_threshold_minsig(&input);
        }
    }
});
