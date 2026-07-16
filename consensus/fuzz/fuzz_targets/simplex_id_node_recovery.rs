#![no_main]

use commonware_consensus_fuzz::{
    SimplexId, fuzz_node,
    simplex_node::{NodeFuzzInput, WithRecovery},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: NodeFuzzInput| {
    fuzz_node::<SimplexId, WithRecovery>(input);
});
