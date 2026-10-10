#![no_main]

use commonware_cryptography::{Keccak256, fuzz::Plan};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|plan: Plan<Keccak256>| plan.run());
