#![no_main]

use commonware_consensus::simplex::{
    mocks::fixtures::{bls12381_multisig, Fixture},
    signing_scheme::bls12381_multisig as multisig_scheme,
};
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexBls12381MultisigMinSig;

impl Simplex for SimplexBls12381MultisigMinSig {
    type Scheme = multisig_scheme::Scheme<Ed25519PublicKey, MinSig>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_multisig::<MinSig, _>(context, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MultisigMinSig>(input);
});
