#![no_main]

use commonware_consensus_fuzz::{
    fuzz, CodeCoverage, FuzzInput, SimplexBls12381MultisigMinSig, Standard,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexBls12381MultisigMinSig, Standard, CodeCoverage>(input);
});
