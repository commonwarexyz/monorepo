#![no_main]

use commonware_consensus::simplex::scheme::bls12381_threshold as threshold_scheme;
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::mocks::Fixture,
    ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexBls12381MinSig;

impl Simplex for SimplexBls12381MinSig {
    type Scheme = threshold_scheme::Scheme<Ed25519PublicKey, MinSig>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        threshold_scheme::fixtures::<MinSig, _>(context, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MinSig>(input);
});
