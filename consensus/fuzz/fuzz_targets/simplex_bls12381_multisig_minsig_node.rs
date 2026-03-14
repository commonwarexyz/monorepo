#![no_main]

use commonware_consensus_fuzz::{
    fuzz_node,
    simplex_node::{NodeFuzzInput, WithoutRecovery},
    SimplexBls12381MultisigMinSig,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: NodeFuzzInput| {
    fuzz_node::<SimplexBls12381MultisigMinSig, WithoutRecovery>(input);
});
