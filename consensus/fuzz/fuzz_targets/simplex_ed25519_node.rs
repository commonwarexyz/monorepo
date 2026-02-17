#![no_main]

use commonware_consensus_fuzz::simplex_node::{fuzz_simplex_node, SimplexNodeFuzzInput};
use libfuzzer_sys::fuzz_target;
use commonware_consensus_fuzz::SimplexEd25519;

fuzz_target!(|input: SimplexNodeFuzzInput| {
    fuzz_simplex_node::<SimplexEd25519>(input);
});