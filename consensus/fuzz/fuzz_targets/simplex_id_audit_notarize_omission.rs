#![no_main]

use commonware_consensus_fuzz::{FuzzInput, SimplexId, fuzz_audit_notarize_omission};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_audit_notarize_omission::<SimplexId>(input);
});
