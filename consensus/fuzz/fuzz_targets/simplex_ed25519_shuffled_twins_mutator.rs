#![no_main]

use commonware_consensus_fuzz::{
    fuzz, CodeCoverage, FuzzInput, SimplexEd25519CustomRoundRobin, TwinsMutator,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519CustomRoundRobin, TwinsMutator, CodeCoverage>(input);
});
