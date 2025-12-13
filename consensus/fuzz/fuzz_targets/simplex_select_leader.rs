#![no_main]
use arbitrary::Arbitrary;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    simplex::{
        scheme::{
            bls12381_multisig,
            bls12381_threshold::{self, Seed},
            ed25519, SeededScheme,
        },
        select_leader,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_math::algebra::Random;
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type Bls12381ThresholdMinPk = bls12381_threshold::Scheme<PublicKey, MinPk>;
type Bls12381ThresholdMinSig = bls12381_threshold::Scheme<PublicKey, MinSig>;

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
    encoded_seed: Vec<u8>,
}

fn fuzz<S: SeededScheme<PublicKey = PublicKey>>(input: &FuzzInput, seed: Option<S::Seed>) {
    let participants: Vec<PublicKey> = (1..=input.participants_count)
        .map(|i| {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let private_key = PrivateKey::random(&mut rng);
            private_key.public_key()
        })
        .collect();
    if participants.is_empty() {
        return;
    }

    let round = Round::new(Epoch::new(input.round_epoch), View::new(input.round_view));
    let _ = select_leader::<S>(&participants, round, seed);
}

fuzz_target!(|input: FuzzInput| {
    match input.scheme {
        FuzzScheme::Ed25519 => {
            fuzz::<Ed25519Scheme>(&input, None);
        }
        FuzzScheme::Bls12381ThresholdMinPk => {
            let seed = Seed::<MinPk>::decode(input.encoded_seed.as_slice()).ok();
            fuzz::<Bls12381ThresholdMinPk>(&input, seed);
        }
        FuzzScheme::Bls12381ThresholdMinSig => {
            let seed = Seed::<MinSig>::decode(input.encoded_seed.as_slice()).ok();
            fuzz::<Bls12381ThresholdMinSig>(&input, seed);
        }
        FuzzScheme::Bls12381MultisigMinPk => {
            fuzz::<Bls12381MultisigMinPk>(&input, None);
        }
        FuzzScheme::Bls12381MultisigMinSig => {
            fuzz::<Bls12381MultisigMinSig>(&input, None);
        }
    }
});
