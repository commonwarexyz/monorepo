#![no_main]

use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_cryptography_fuzz::certificate::{FuzzInput, Multisig, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Multisig<MinSig>>(input);
});
