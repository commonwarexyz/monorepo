#![no_main]

use commonware_consensus::simplex::{
    mocks::fixtures::{ed25519, Fixture},
    signing_scheme::ed25519 as ed25519_scheme,
};
use commonware_consensus_fuzz::{fuzz, FuzzInput, Simplex};
use commonware_runtime::deterministic;
use libfuzzer_sys::fuzz_target;

struct SimplexEd25519;

impl Simplex for SimplexEd25519 {
    type Scheme = ed25519_scheme::Scheme;

    fn fixture(context: &mut deterministic::Context, n: u32) -> Fixture<Self::Scheme> {
        ed25519(context, n)
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519>(input);
});
