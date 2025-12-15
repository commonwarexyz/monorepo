#![no_main]

use commonware_consensus::simplex::scheme::ed25519 as ed25519_scheme;
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_cryptography::certificate::mocks::Fixture;
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexEd25519;

impl Simplex for SimplexEd25519 {
    type Scheme = ed25519_scheme::Scheme;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        ed25519_scheme::fixtures(context, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519>(input);
});
