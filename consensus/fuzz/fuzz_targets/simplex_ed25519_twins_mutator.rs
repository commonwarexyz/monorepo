#![no_main]

use commonware_consensus_fuzz::{CodeCoverage, FuzzInput, SimplexEd25519, TwinsMutator, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519, TwinsMutator, CodeCoverage>(input);
});
