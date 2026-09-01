#![no_main]

use commonware_consensus_fuzz::multimmit_engine;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| multimmit_engine::fuzz::<MinPk>(input));
