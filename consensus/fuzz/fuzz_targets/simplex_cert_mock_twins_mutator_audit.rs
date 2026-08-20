#![no_main]

use commonware_consensus_fuzz::{
    FuzzInput, SimplexCertificateMock, TwinsMutator, fuzz_twins_audit,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_twins_audit::<SimplexCertificateMock, TwinsMutator>(input);
});
