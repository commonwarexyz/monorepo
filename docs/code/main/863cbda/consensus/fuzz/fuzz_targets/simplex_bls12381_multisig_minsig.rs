#![no_main]

use commonware_consensus::simplex::{elector::RoundRobin, scheme::bls12381_multisig};
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::mocks::Fixture,
    ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexBls12381MultisigMinSig;

impl Simplex for SimplexBls12381MultisigMinSig {
    type Scheme = bls12381_multisig::Scheme<Ed25519PublicKey, MinSig>;
    type Elector = RoundRobin;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_multisig::fixture::<MinSig, _>(context, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MultisigMinSig>(input);
});
