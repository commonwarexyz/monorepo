#![no_main]

use commonware_consensus::simplex::{elector::RoundRobin, scheme::secp256r1};
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::{
    certificate::mocks::Fixture, ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexSecp256r1;

impl Simplex for SimplexSecp256r1 {
    type Scheme = secp256r1::Scheme<Ed25519PublicKey>;
    type Elector = RoundRobin;

    fn fixture(
        context: &mut deterministic::Context,
        namespace: &[u8],
        n: u32,
    ) -> Fixture<Self::Scheme> {
        secp256r1::fixture(context, namespace, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexSecp256r1>(input);
});
