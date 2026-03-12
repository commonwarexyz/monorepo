#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        fuzz_node,
        simplex_node::{NodeFuzzInput, WithRecovery},
        SimplexCertificateMock,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: NodeFuzzInput| {
        fuzz_node::<SimplexCertificateMock, WithRecovery>(input);
    });
}
