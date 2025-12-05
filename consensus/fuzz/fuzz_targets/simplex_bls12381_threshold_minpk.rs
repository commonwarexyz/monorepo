#![no_main]

use commonware_consensus::simplex::{
    mocks::fixtures::{bls12381_threshold, Fixture},
    signing_scheme::bls12381_threshold as threshold_scheme,
};
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk, ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexBls12381MinPk;

impl Simplex for SimplexBls12381MinPk {
    type Scheme = threshold_scheme::Scheme<Ed25519PublicKey, MinPk>;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        bls12381_threshold::<MinPk, _>(context, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MinPk>(input);
});
