#![no_main]

use commonware_consensus_fuzz::{
    simplex_node::{fuzz_simplex_node, SimplexNodeFuzzInput},
    SimplexEd25519,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: SimplexNodeFuzzInput| {
    fuzz_simplex_node::<SimplexEd25519>(input);
});
