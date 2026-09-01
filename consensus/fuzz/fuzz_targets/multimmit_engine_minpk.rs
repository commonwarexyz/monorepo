#![no_main]

use commonware_consensus::fuzz::multimmit;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| multimmit::fuzz::<MinPk>(input));
