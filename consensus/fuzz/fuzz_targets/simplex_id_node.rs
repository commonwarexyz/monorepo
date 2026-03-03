#![no_main]

use commonware_consensus_fuzz::{
    fuzz_node,
    simplex_node::{NodeFuzzInput, WithoutRecovery},
    SimplexId,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: NodeFuzzInput| {
    fuzz_node::<SimplexId, WithoutRecovery>(input);
});
