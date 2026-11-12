#![no_main]

use commonware_consensus::multimmit::test_utils::fuzz_artifacts;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| fuzz_artifacts(input));
