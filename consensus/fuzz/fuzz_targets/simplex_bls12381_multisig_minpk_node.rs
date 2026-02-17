#![no_main]

use commonware_consensus_fuzz::simplex_node::{fuzz_simplex_node, SimplexNodeFuzzInput};
use libfuzzer_sys::fuzz_target;
use commonware_consensus_fuzz::SimplexBls12381MultisigMinPk;

fuzz_target!(|input: SimplexNodeFuzzInput| {
    fuzz_simplex_node::<SimplexBls12381MultisigMinPk>(input);
});
