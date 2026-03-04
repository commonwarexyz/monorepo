#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexBls12381MultisigMinPk, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MultisigMinPk, Standard>(input);
});
