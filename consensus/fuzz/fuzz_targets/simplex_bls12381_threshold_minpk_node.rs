#![no_main]

use commonware_consensus_fuzz::{
    simplex_node::{fuzz_simplex_node, SimplexNodeFuzzInput},
    SimplexBls12381MinPk,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: SimplexNodeFuzzInput| {
    fuzz_simplex_node::<SimplexBls12381MinPk>(input);
});
