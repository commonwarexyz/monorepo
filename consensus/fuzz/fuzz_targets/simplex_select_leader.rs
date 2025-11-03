#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::ReadExt;
use commonware_consensus::{
    simplex::{
        select_leader,
        signing_scheme::{
            bls12381_multisig,
            bls12381_threshold::{self, Seed},
            ed25519, Scheme,
        },
    },
    types::Round,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Element, G1, G1_ELEMENT_BYTE_LENGTH, G2, G2_ELEMENT_BYTE_LENGTH},
        variant::{MinPk, MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
    PrivateKeyExt, Signer,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type Bls12381ThresholdMinPk = bls12381_threshold::Scheme<PublicKey, MinPk>;
type Bls12381ThresholdMinSig = bls12381_threshold::Scheme<PublicKey, MinSig>;

fn arbitrary_g1(u: &mut Unstructured) -> Result<G1, arbitrary::Error> {
    let bytes: [u8; G1_ELEMENT_BYTE_LENGTH] = u.arbitrary()?;
    match G1::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G1::zero()
        } else {
            G1::one()
        }),
    }
}

fn arbitrary_g2(u: &mut Unstructured) -> Result<G2, arbitrary::Error> {
    let bytes: [u8; G2_ELEMENT_BYTE_LENGTH] = u.arbitrary()?;
    match G2::read(&mut bytes.as_slice()) {
        Ok(point) => Ok(point),
        Err(_) => Ok(if u.arbitrary()? {
            G2::zero()
        } else {
            G2::one()
        }),
    }
}

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
    round_epoch: u64,
    round_view: u64,
    scheme: FuzzScheme,
    #[arbitrary(with = arbitrary_g1)]
    signature_g1: G1,
    #[arbitrary(with = arbitrary_g2)]
    signature_g2: G2,
}

fn fuzz<S: Scheme>(input: &FuzzInput, seed: S::Seed) {
    let participants: Vec<PublicKey> = (1..=input.participants_count)
        .map(|i| {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let private_key = PrivateKey::from_rng(&mut rng);
            private_key.public_key()
        })
        .collect();
    if participants.is_empty() {
        return;
    }

    let _ = select_leader::<S, PublicKey>(&participants, seed);
}

fuzz_target!(|input: FuzzInput| {
    match input.scheme {
        FuzzScheme::Ed25519 => {
            let seed = (input.round_epoch, input.round_view);
            fuzz::<Ed25519Scheme>(&input, seed);
        }
        FuzzScheme::Bls12381ThresholdMinPk => {
            let seed = Seed::<MinPk>::new(
                Round::new(input.round_epoch, input.round_view),
                input.signature_g2,
            );
            fuzz::<Bls12381ThresholdMinPk>(&input, seed);
        }
        FuzzScheme::Bls12381ThresholdMinSig => {
            let seed = Seed::<MinSig>::new(
                Round::new(input.round_epoch, input.round_view),
                input.signature_g1,
            );
            fuzz::<Bls12381ThresholdMinSig>(&input, seed);
        }
        FuzzScheme::Bls12381MultisigMinPk => {
            let seed = (input.round_epoch, input.round_view);
            fuzz::<Bls12381MultisigMinPk>(&input, seed);
        }
        FuzzScheme::Bls12381MultisigMinSig => {
            let seed = (input.round_epoch, input.round_view);
            fuzz::<Bls12381MultisigMinSig>(&input, seed);
        }
    }
});
