#![no_main]

use commonware_consensus::simplex::{
    elector::Random, scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
};
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
    ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexBls12381MinPk;

impl Simplex for SimplexBls12381MinPk {
    type Scheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinPk>;
    type Elector = Random;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        bls12381_threshold_vrf::fixture::<MinPk, _>(context, namespace, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MinPk>(input);
});
