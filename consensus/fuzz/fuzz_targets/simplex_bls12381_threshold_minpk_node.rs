#![no_main]

use commonware_consensus_fuzz::{
    simplex_node::{fuzz_node, NodeFuzzInput, WithoutRecovery},
    SimplexBls12381MinPk,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: NodeFuzzInput| {
    fuzz_node::<SimplexBls12381MinPk, WithoutRecovery>(input);
});
