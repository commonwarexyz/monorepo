//! The runtime storage contract under injected failures and simulated crashes. The harness is
//! `commonware_runtime_fuzz::storage_faults`; see `runtime/fuzz/SPEC.md`.

#![no_main]

use commonware_runtime_fuzz::storage_faults::{FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
