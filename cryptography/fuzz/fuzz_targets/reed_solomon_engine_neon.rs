#![no_main]

#[cfg(target_arch = "aarch64")]
use commonware_cryptography::reed_solomon::engine::Neon;
#[cfg(target_arch = "aarch64")]
use commonware_cryptography_fuzz::reed_solomon::{FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

#[cfg(target_arch = "aarch64")]
fuzz_target!(|input: FuzzInput| {
    if std::arch::is_aarch64_feature_detected!("neon") {
        fuzz::<Neon>(input);
    }
});

#[cfg(not(target_arch = "aarch64"))]
fuzz_target!(|_input: &[u8]| {});
