#![no_main]

use commonware_consensus_fuzz::{
    SimplexEd25519, fuzz_node,
    simplex_node::{NodeFuzzInput, WithoutRecovery},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: NodeFuzzInput| {
    fuzz_node::<SimplexEd25519, WithoutRecovery>(input);
});
