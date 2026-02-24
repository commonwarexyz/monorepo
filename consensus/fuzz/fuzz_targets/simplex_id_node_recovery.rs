#![no_main]

use commonware_consensus_fuzz::{
    simplex_node::{fuzz_node, NodeFuzzInput, WithRecovery},
    SimplexId,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: NodeFuzzInput| {
    fuzz_node::<SimplexId, WithRecovery>(input);
});
