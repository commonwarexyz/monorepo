#![no_main]
use arbitrary::Arbitrary;
use commonware_codec::Decode;
use commonware_consensus::{
    simplex::{
        select_leader,
        signing_scheme::{bls12381_threshold::Seed, Scheme},
    },
    types::Round,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    ed25519::{PrivateKey, PublicKey},
    PrivateKeyExt, Signer,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

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

type Ed25519Scheme = commonware_consensus::simplex::signing_scheme::ed25519::Scheme;
type Bls12381MultisigMinPk =
    commonware_consensus::simplex::signing_scheme::bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig =
    commonware_consensus::simplex::signing_scheme::bls12381_multisig::Scheme<PublicKey, MinSig>;

type Bls12381ThresholdMinPk =
    commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<PublicKey, MinPk>;
type Bls12381ThresholdMinSig =
    commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<PublicKey, MinSig>;

fn fuzz<S: Scheme>(input: &FuzzInput, seed: Option<S::Seed>) {
    let participants: Vec<PublicKey> = (0..input.participants_count)
        .map(|i| {
            let mut rng = StdRng::seed_from_u64(i as u64);
            let private_key = PrivateKey::from_rng(&mut rng);
            private_key.public_key()
        })
        .collect();

    if participants.is_empty() {
        return;
    }

    let round = Round::new(input.round_epoch, input.round_view);
    let _ = select_leader::<S, PublicKey>(&participants, round, seed);
}

fuzz_target!(|input: FuzzInput| {
    match input.scheme {
        FuzzScheme::Ed25519 => {
            fuzz::<Ed25519Scheme>(&input, None);
        }
        FuzzScheme::Bls12381ThresholdMinPk => {
            let seed = Seed::<MinPk>::decode_cfg(input.encoded_seed.as_slice(), &()).ok();
            fuzz::<Bls12381ThresholdMinPk>(&input, seed);
        }
        FuzzScheme::Bls12381ThresholdMinSig => {
            let seed = Seed::<MinSig>::decode_cfg(input.encoded_seed.as_slice(), &()).ok();
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
