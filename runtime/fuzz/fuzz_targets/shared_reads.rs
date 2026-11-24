//! Concurrent readers that share the page reads of one page cache. The harness is
//! `commonware_runtime_fuzz::shared_reads`; see `runtime/fuzz/SPEC.md`.

#![no_main]

use commonware_runtime_fuzz::shared_reads::{FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
