#![no_main]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use commonware_cryptography::reed_solomon::engine::Ssse3;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use commonware_cryptography_fuzz::reed_solomon::{FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fuzz_target!(|input: FuzzInput| {
    if std::arch::is_x86_feature_detected!("ssse3") {
        fuzz::<Ssse3>(input);
    }
});

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fuzz_target!(|_input: &[u8]| {});
