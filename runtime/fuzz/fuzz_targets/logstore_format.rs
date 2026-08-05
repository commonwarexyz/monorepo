//! Fuzz test for the log-storage on-disk format.
//!
//! Feeds arbitrary bytes to every hostile-input decode surface of the
//! format layer (record tail decode under each reader expectation, root
//! decode for both slots, checkpoint decode from a located range). The
//! driver asserts no panics, allocation bounded by the decode budget, and
//! that any accepted value re-encodes byte-identically to the input it was
//! decoded from.

#![no_main]

use commonware_runtime::logstore_fuzz::decode_surfaces;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    decode_surfaces(data);
});
