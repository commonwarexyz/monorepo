#![no_main]

use commonware_consensus::multimmit::test_utils::fuzz_algebra;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| fuzz_algebra(input));
